import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'events';
import type { AddressInfo } from 'net';
import type { SshTunnelConfig } from '../src/types.js';

// ── mock net ──────────────────────────────────────────────────────────────────

const mockServerAddress: AddressInfo = { address: '127.0.0.1', family: 'IPv4', port: 54321 };

const mockServer = {
  listen: vi.fn((_port: any, _host: any, cb: () => void) => process.nextTick(cb)),
  close: vi.fn(),
  on: vi.fn(),
  address: vi.fn(() => mockServerAddress),
};

vi.mock('net', () => ({
  default: {
    createServer: vi.fn(() => mockServer),
  },
}));

// ── mock ssh2 ─────────────────────────────────────────────────────────────────

class MockSshClient extends EventEmitter {
  connect = vi.fn((_cfg: any) => {
    process.nextTick(() => this.emit('ready'));
  });
  forwardOut = vi.fn();
  end = vi.fn(() => {
    this.emit('end');
  });
}

let mockSshClientInstance: MockSshClient;

vi.mock('ssh2', () => ({
  Client: class {
    constructor() {
      mockSshClientInstance = new MockSshClient();
      return mockSshClientInstance;
    }
  },
}));

// ── mock fs ───────────────────────────────────────────────────────────────────
// `import fs from 'fs'` binds to the `default` export. For CJS modules wrapped
// as ESM, spreading `actual` does NOT override `default`, so we must set it
// explicitly to make `fs.readFileSync` point to our vi.fn.

const mockReadFileSync = vi.fn((p: any) => {
  if (String(p).includes('id_rsa')) return Buffer.from('MOCK_PRIVATE_KEY');
  throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
});

vi.mock('fs', async (importOriginal) => {
  const actual = (await importOriginal()) as any;
  return {
    ...actual,
    default: { ...(actual.default ?? actual), readFileSync: mockReadFileSync },
    readFileSync: mockReadFileSync,
  };
});

// ── helpers ───────────────────────────────────────────────────────────────────

const baseConfig: SshTunnelConfig = {
  host: 'bastion.example.com',
  port: 22,
  user: 'ssh-user',
  authType: 'PASSWORD',
  password: 'secret',
};

// ── tests ─────────────────────────────────────────────────────────────────────

describe('SshTunnelManager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Re-wire listen mock after clearAllMocks resets its implementation
    mockServer.listen.mockImplementation((_port: any, _host: any, cb: () => void) =>
      process.nextTick(cb)
    );
    mockReadFileSync.mockImplementation((p: any) => {
      if (String(p).includes('id_rsa')) return Buffer.from('MOCK_PRIVATE_KEY');
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    });
  });

  it('creates a tunnel and returns the local port', async () => {
    const { SshTunnelManager } = await import('../src/ssh-tunnel.js');
    const manager = new SshTunnelManager();

    const port = await manager.getTunnel('key1', baseConfig, 'db.internal', 5432);

    expect(port).toBe(54321);
    expect(mockSshClientInstance.connect).toHaveBeenCalledWith(
      expect.objectContaining({
        host: 'bastion.example.com',
        port: 22,
        username: 'ssh-user',
        password: 'secret',
      })
    );
  });

  it('reuses an existing tunnel on repeated calls', async () => {
    const { SshTunnelManager } = await import('../src/ssh-tunnel.js');
    const manager = new SshTunnelManager();

    const port1 = await manager.getTunnel('key1', baseConfig, 'db.internal', 5432);
    const clientAfterFirst = mockSshClientInstance;
    const port2 = await manager.getTunnel('key1', baseConfig, 'db.internal', 5432);

    expect(port1).toBe(port2);
    // Same SSH client — connect only fired once
    expect(mockSshClientInstance).toBe(clientAfterFirst);
    expect(clientAfterFirst.connect).toHaveBeenCalledTimes(1);
  });

  it('uses different SSH clients for different tunnel keys', async () => {
    const { SshTunnelManager } = await import('../src/ssh-tunnel.js');
    const manager = new SshTunnelManager();

    await manager.getTunnel('key1', baseConfig, 'db1.internal', 5432);
    const firstClient = mockSshClientInstance;

    await manager.getTunnel('key2', baseConfig, 'db2.internal', 5432);
    const secondClient = mockSshClientInstance;

    expect(firstClient).not.toBe(secondClient);
  });

  it('uses the private key when authType is PUBLIC_KEY', async () => {
    const { SshTunnelManager } = await import('../src/ssh-tunnel.js');
    const manager = new SshTunnelManager();

    const pkConfig: SshTunnelConfig = {
      host: 'bastion.example.com',
      port: 22,
      user: 'ec2-user',
      authType: 'PUBLIC_KEY',
      privateKeyPath: '/home/user/.ssh/id_rsa',
    };

    await manager.getTunnel('pk-key', pkConfig, 'db.internal', 5432);

    expect(mockSshClientInstance.connect).toHaveBeenCalledWith(
      expect.objectContaining({ privateKey: Buffer.from('MOCK_PRIVATE_KEY') })
    );
    expect(mockSshClientInstance.connect).toHaveBeenCalledWith(
      expect.not.objectContaining({ password: expect.anything() })
    );
  });

  it('falls back to password when private key file is unreadable', async () => {
    const { SshTunnelManager } = await import('../src/ssh-tunnel.js');
    const manager = new SshTunnelManager();

    mockReadFileSync.mockImplementation(() => {
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    });

    const fallbackConfig: SshTunnelConfig = {
      host: 'bastion.example.com',
      port: 22,
      user: 'ssh-user',
      authType: 'PUBLIC_KEY',
      privateKeyPath: '/nonexistent/key',
      password: 'fallback-password',
    };

    await manager.getTunnel('fb-key', fallbackConfig, 'db.internal', 5432);

    expect(mockSshClientInstance.connect).toHaveBeenCalledWith(
      expect.objectContaining({ password: 'fallback-password' })
    );
  });

  it('closeTunnel is a no-op for unknown keys', async () => {
    const { SshTunnelManager } = await import('../src/ssh-tunnel.js');
    const manager = new SshTunnelManager();

    expect(() => manager.closeTunnel('nonexistent')).not.toThrow();
  });

  it('closeTunnel ends the SSH client and closes the server', async () => {
    const { SshTunnelManager } = await import('../src/ssh-tunnel.js');
    const manager = new SshTunnelManager();

    await manager.getTunnel('key1', baseConfig, 'db.internal', 5432);
    const client = mockSshClientInstance;
    manager.closeTunnel('key1');

    expect(mockServer.close).toHaveBeenCalledTimes(1);
    expect(client.end).toHaveBeenCalledTimes(1);
  });

  it('closeAllTunnels is a no-op when no tunnels exist', async () => {
    const { SshTunnelManager } = await import('../src/ssh-tunnel.js');
    const manager = new SshTunnelManager();

    expect(() => manager.closeAllTunnels()).not.toThrow();
  });

  it('closeAllTunnels closes every open tunnel', async () => {
    const { SshTunnelManager } = await import('../src/ssh-tunnel.js');
    const manager = new SshTunnelManager();

    await manager.getTunnel('key1', baseConfig, 'db1.internal', 5432);
    const client1 = mockSshClientInstance;
    await manager.getTunnel('key2', baseConfig, 'db2.internal', 5432);
    const client2 = mockSshClientInstance;

    manager.closeAllTunnels();

    expect(client1.end).toHaveBeenCalledTimes(1);
    expect(client2.end).toHaveBeenCalledTimes(1);
    expect(mockServer.close).toHaveBeenCalledTimes(2);
  });

  it('removes tunnel from cache when SSH client disconnects', async () => {
    const { SshTunnelManager } = await import('../src/ssh-tunnel.js');
    const manager = new SshTunnelManager();

    await manager.getTunnel('key1', baseConfig, 'db.internal', 5432);
    const firstClient = mockSshClientInstance;

    // Simulate SSH server dropping the connection
    firstClient.emit('end');

    // Next getTunnel must create a brand-new SSH client (cache was invalidated)
    await manager.getTunnel('key1', baseConfig, 'db.internal', 5432);

    expect(mockSshClientInstance).not.toBe(firstClient);
    expect(mockSshClientInstance.connect).toHaveBeenCalledTimes(1);
  });
});
