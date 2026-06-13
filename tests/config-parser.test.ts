import { describe, it, expect, beforeEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';

// Mock fs module
vi.mock('fs');
vi.mock('os');

describe('WorkspaceConfigParser', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(os.platform).mockReturnValue('darwin');
    vi.mocked(os.homedir).mockReturnValue('/Users/test');
  });

  describe('getDefaultWorkspacePath', () => {
    it('should return macOS path on darwin', async () => {
      vi.mocked(os.platform).mockReturnValue('darwin');
      vi.mocked(fs.existsSync).mockReturnValue(false);

      // Dynamic import to get fresh instance
      const { WorkspaceConfigParser } = await import('../src/config-parser.js');
      const parser = new WorkspaceConfigParser({});

      expect(parser.getWorkspacePath()).toContain('Library/DBeaverData');
    });
  });

  describe('parseConnections', () => {
    it('should return empty array when no config exists', async () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);

      const { WorkspaceConfigParser } = await import('../src/config-parser.js');
      const parser = new WorkspaceConfigParser({});

      const connections = await parser.parseConnections();
      expect(connections).toEqual([]);
    });
  });

  describe('SSH tunnel parsing (new JSON format)', () => {
    const makeJsonConfig = (sshHandler?: object, extraConnConfig?: object) => ({
      connections: {
        'conn-1': {
          name: 'Test DB',
          driver: 'postgresql:pg',
          configuration: {
            host: 'db.example.com',
            port: 5432,
            database: 'mydb',
            user: 'dbuser',
            ...extraConnConfig,
            ...(sshHandler ? { handlers: { ssh_tunnel: sshHandler } } : {}),
          },
        },
      },
    });

    function mockNewFormat(jsonContent: string) {
      vi.mocked(fs.existsSync).mockImplementation((p) => {
        const s = String(p);
        return s.endsWith('data-sources.json') || s.includes('General/.dbeaver');
      });
      vi.mocked(fs.readFileSync).mockImplementation((p: any) => {
        if (String(p).endsWith('data-sources.json')) return jsonContent;
        throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      });
    }

    it('should parse SSH tunnel with password auth', async () => {
      const config = makeJsonConfig({
        enabled: true,
        properties: {
          host: 'bastion.example.com',
          port: '2222',
          user: 'ssh-user',
          authType: 'PASSWORD',
          connectTimeout: '5000',
        },
      });
      mockNewFormat(JSON.stringify(config));

      const { WorkspaceConfigParser } = await import('../src/config-parser.js');
      const parser = new WorkspaceConfigParser({});
      const connections = await parser.parseConnections();

      expect(connections).toHaveLength(1);
      const tunnel = connections[0].sshTunnel;
      expect(tunnel).toBeDefined();
      expect(tunnel?.host).toBe('bastion.example.com');
      expect(tunnel?.port).toBe(2222);
      expect(tunnel?.user).toBe('ssh-user');
      expect(tunnel?.authType).toBe('PASSWORD');
      expect(tunnel?.connectTimeout).toBe(5000);
    });

    it('should parse SSH tunnel with public key auth', async () => {
      const config = makeJsonConfig({
        enabled: true,
        properties: {
          host: 'jump.example.com',
          port: '22',
          user: 'ec2-user',
          authType: 'PUBLIC_KEY',
          keyPath: '/home/user/.ssh/id_rsa',
          keepAliveInterval: '30',
        },
      });
      mockNewFormat(JSON.stringify(config));

      const { WorkspaceConfigParser } = await import('../src/config-parser.js');
      const parser = new WorkspaceConfigParser({});
      const connections = await parser.parseConnections();

      const tunnel = connections[0].sshTunnel;
      expect(tunnel?.authType).toBe('PUBLIC_KEY');
      expect(tunnel?.privateKeyPath).toBe('/home/user/.ssh/id_rsa');
      expect(tunnel?.keepAliveInterval).toBe(30);
    });

    it('should not set sshTunnel when handler is disabled', async () => {
      const config = makeJsonConfig({
        enabled: false,
        properties: { host: 'bastion.example.com', port: '22', user: 'ssh-user' },
      });
      mockNewFormat(JSON.stringify(config));

      const { WorkspaceConfigParser } = await import('../src/config-parser.js');
      const parser = new WorkspaceConfigParser({});
      const connections = await parser.parseConnections();

      expect(connections[0].sshTunnel).toBeUndefined();
    });

    it('should not set sshTunnel when no handlers are configured', async () => {
      const config = makeJsonConfig();
      mockNewFormat(JSON.stringify(config));

      const { WorkspaceConfigParser } = await import('../src/config-parser.js');
      const parser = new WorkspaceConfigParser({});
      const connections = await parser.parseConnections();

      expect(connections[0].sshTunnel).toBeUndefined();
    });

    it('should default port to 22 when not specified', async () => {
      const config = makeJsonConfig({
        enabled: true,
        properties: { host: 'bastion.example.com', user: 'ssh-user' },
      });
      mockNewFormat(JSON.stringify(config));

      const { WorkspaceConfigParser } = await import('../src/config-parser.js');
      const parser = new WorkspaceConfigParser({});
      const connections = await parser.parseConnections();

      expect(connections[0].sshTunnel?.port).toBe(22);
    });
  });

  describe('SSH tunnel parsing (old XML format)', () => {
    function mockOldFormat(xmlContent: string) {
      vi.mocked(fs.existsSync).mockImplementation((p) => {
        const s = String(p);
        return s.endsWith('connections.xml') || s.includes('.metadata');
      });
      vi.mocked(fs.readFileSync).mockImplementation((p: any) => {
        if (String(p).endsWith('connections.xml')) return xmlContent;
        throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      });
    }

    it('should parse SSH tunnel handler from XML format', async () => {
      const xml = `<?xml version="1.0" encoding="utf-8"?>
<connections>
  <connection id="mysql-1" name="Test MySQL" driver="mysql:mysql8" folder="">
    <property name="host" value="db.example.com"/>
    <property name="port" value="3306"/>
    <property name="database" value="mydb"/>
    <property name="user" value="dbuser"/>
    <handler id="ssh_tunnel" enabled="true" save-password="true">
      <property name="host" value="bastion.example.com"/>
      <property name="port" value="22"/>
      <property name="user" value="ssh-user"/>
      <property name="authType" value="PUBLIC_KEY"/>
      <property name="keyPath" value="/home/user/.ssh/id_rsa"/>
    </handler>
  </connection>
</connections>`;
      mockOldFormat(xml);

      const { WorkspaceConfigParser } = await import('../src/config-parser.js');
      const parser = new WorkspaceConfigParser({});
      const connections = await parser.parseConnections();

      expect(connections).toHaveLength(1);
      const tunnel = connections[0].sshTunnel;
      expect(tunnel).toBeDefined();
      expect(tunnel?.host).toBe('bastion.example.com');
      expect(tunnel?.port).toBe(22);
      expect(tunnel?.user).toBe('ssh-user');
      expect(tunnel?.authType).toBe('PUBLIC_KEY');
      expect(tunnel?.privateKeyPath).toBe('/home/user/.ssh/id_rsa');
    });

    it('should not set sshTunnel when XML handler is disabled', async () => {
      const xml = `<?xml version="1.0" encoding="utf-8"?>
<connections>
  <connection id="pg-1" name="Test PG" driver="postgresql:pg" folder="">
    <property name="host" value="db.example.com"/>
    <handler id="ssh_tunnel" enabled="false">
      <property name="host" value="bastion.example.com"/>
      <property name="port" value="22"/>
      <property name="user" value="ssh-user"/>
    </handler>
  </connection>
</connections>`;
      mockOldFormat(xml);

      const { WorkspaceConfigParser } = await import('../src/config-parser.js');
      const parser = new WorkspaceConfigParser({});
      const connections = await parser.parseConnections();

      expect(connections[0].sshTunnel).toBeUndefined();
    });

    it('should not set sshTunnel when no handler in XML', async () => {
      const xml = `<?xml version="1.0" encoding="utf-8"?>
<connections>
  <connection id="pg-1" name="Test PG" driver="postgresql:pg" folder="">
    <property name="host" value="db.example.com"/>
  </connection>
</connections>`;
      mockOldFormat(xml);

      const { WorkspaceConfigParser } = await import('../src/config-parser.js');
      const parser = new WorkspaceConfigParser({});
      const connections = await parser.parseConnections();

      expect(connections[0].sshTunnel).toBeUndefined();
    });
  });
});
