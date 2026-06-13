import net from 'net';
import fs from 'fs';
import { Client, ConnectConfig } from 'ssh2';
import { JumpServerConfig, SshTunnelConfig } from './types.js';

interface TunnelEntry {
  sshClient: Client;
  server: net.Server;
  localPort: number;
}

export class SshTunnelManager {
  private tunnels: Map<string, TunnelEntry> = new Map();
  private debug: boolean;

  constructor(debug = false) {
    this.debug = debug;
  }

  private log(msg: string): void {
    if (this.debug) console.error(`[SshTunnel] ${msg}`);
  }

  async getTunnel(
    tunnelKey: string,
    sshConfig: SshTunnelConfig,
    remoteHost: string,
    remotePort: number
  ): Promise<number> {
    const existing = this.tunnels.get(tunnelKey);
    if (existing) {
      this.log(`Reusing SSH tunnel ${tunnelKey} on local port ${existing.localPort}`);
      return existing.localPort;
    }

    this.log(`Creating SSH tunnel ${tunnelKey}: ${sshConfig.host} -> ${remoteHost}:${remotePort}`);
    const entry = await this.createTunnel(tunnelKey, sshConfig, remoteHost, remotePort);
    this.tunnels.set(tunnelKey, entry);
    return entry.localPort;
  }

  private buildConnectConfig(
    sshConfig: SshTunnelConfig | JumpServerConfig,
    extra?: Partial<ConnectConfig>
  ): ConnectConfig {
    const connectConfig: ConnectConfig = {
      username: sshConfig.user,
      readyTimeout: (sshConfig as SshTunnelConfig).connectTimeout || 10000,
      ...extra,
    };

    if (!extra?.sock) {
      connectConfig.host = sshConfig.host;
      connectConfig.port = sshConfig.port || 22;
    }

    const useKey =
      sshConfig.authType === 'PUBLIC_KEY' ||
      (!('password' in sshConfig && sshConfig.password) && sshConfig.privateKeyPath);

    if (useKey && sshConfig.privateKeyPath) {
      try {
        connectConfig.privateKey = fs.readFileSync(sshConfig.privateKeyPath);
      } catch {
        // fall through to password auth
      }
    }

    if (sshConfig.passphrase) {
      connectConfig.passphrase = sshConfig.passphrase;
    }

    if ('password' in sshConfig && sshConfig.password && !connectConfig.privateKey) {
      connectConfig.password = sshConfig.password;
    }

    if ('keepAliveInterval' in sshConfig && sshConfig.keepAliveInterval && sshConfig.keepAliveInterval > 0) {
      connectConfig.keepaliveInterval = sshConfig.keepAliveInterval * 1000;
    }

    return connectConfig;
  }

  private attachForwardingServer(
    tunnelKey: string,
    sshClient: Client,
    remoteHost: string,
    remotePort: number,
    resolve: (entry: TunnelEntry) => void,
    reject: (err: Error) => void,
    extraClients: Client[] = []
  ): void {
    const server = net.createServer((socket) => {
      sshClient.forwardOut('127.0.0.1', 0, remoteHost, remotePort, (err, stream) => {
        if (err) {
          this.log(`forwardOut error: ${err.message}`);
          socket.destroy(err);
          return;
        }
        socket.pipe(stream);
        stream.pipe(socket);
        stream.on('close', () => socket.destroy());
        socket.on('close', () => stream.destroy());
        socket.on('error', () => stream.destroy());
        stream.on('error', () => socket.destroy());
      });
    });

    server.listen(0, '127.0.0.1', () => {
      const localPort = (server.address() as net.AddressInfo).port;
      this.log(`SSH tunnel ready on 127.0.0.1:${localPort}`);
      sshClient.on('error', (err) => {
        this.log(`SSH client error (post-connect) for ${tunnelKey}: ${err.message}`);
        this.tunnels.delete(tunnelKey);
      });
      sshClient.on('end', () => {
        this.log(`SSH client disconnected for ${tunnelKey}`);
        this.tunnels.delete(tunnelKey);
        for (const c of extraClients) c.end();
      });
      resolve({ sshClient, server, localPort });
    });

    server.on('error', (err) => {
      sshClient.end();
      for (const c of extraClients) c.end();
      reject(err);
    });
  }

  private createTunnel(
    tunnelKey: string,
    sshConfig: SshTunnelConfig,
    remoteHost: string,
    remotePort: number
  ): Promise<TunnelEntry> {
    return new Promise((resolve, reject) => {
      if (sshConfig.jumpServer) {
        this.createTunnelViaJump(tunnelKey, sshConfig, remoteHost, remotePort, resolve, reject);
      } else {
        this.createDirectTunnel(tunnelKey, sshConfig, remoteHost, remotePort, resolve, reject);
      }
    });
  }

  private createDirectTunnel(
    tunnelKey: string,
    sshConfig: SshTunnelConfig,
    remoteHost: string,
    remotePort: number,
    resolve: (entry: TunnelEntry) => void,
    reject: (err: Error) => void
  ): void {
    const sshClient = new Client();

    const onError = (err: Error) => {
      this.log(`SSH client error for ${tunnelKey}: ${err.message}`);
      this.tunnels.delete(tunnelKey);
      reject(err);
    };

    sshClient.on('ready', () => {
      this.log(`SSH connected to ${sshConfig.host}`);
      sshClient.off('error', onError);
      this.attachForwardingServer(tunnelKey, sshClient, remoteHost, remotePort, resolve, reject);
    });

    sshClient.on('error', onError);
    sshClient.connect(this.buildConnectConfig(sshConfig));
  }

  private createTunnelViaJump(
    tunnelKey: string,
    sshConfig: SshTunnelConfig,
    remoteHost: string,
    remotePort: number,
    resolve: (entry: TunnelEntry) => void,
    reject: (err: Error) => void
  ): void {
    const jump = sshConfig.jumpServer!;
    const jumpClient = new Client();

    const onJumpError = (err: Error) => {
      this.log(`Jump SSH error for ${tunnelKey}: ${err.message}`);
      reject(err);
    };

    jumpClient.on('ready', () => {
      this.log(`Jump SSH connected to ${jump.host}, opening stream to ${sshConfig.host}:${sshConfig.port || 22}`);
      jumpClient.off('error', onJumpError);

      jumpClient.forwardOut('127.0.0.1', 0, sshConfig.host, sshConfig.port || 22, (err, stream) => {
        if (err) {
          jumpClient.end();
          reject(err);
          return;
        }

        const mainClient = new Client();
        const onMainError = (err: Error) => {
          this.log(`Main SSH error via jump for ${tunnelKey}: ${err.message}`);
          jumpClient.end();
          reject(err);
        };

        mainClient.on('ready', () => {
          this.log(`Main SSH connected to ${sshConfig.host} via jump ${jump.host}`);
          mainClient.off('error', onMainError);
          this.attachForwardingServer(
            tunnelKey, mainClient, remoteHost, remotePort, resolve, reject, [jumpClient]
          );
        });

        mainClient.on('error', onMainError);
        mainClient.connect(this.buildConnectConfig(sshConfig, { sock: stream }));
      });
    });

    jumpClient.on('error', onJumpError);
    jumpClient.connect(this.buildConnectConfig(jump));
  }

  closeTunnel(tunnelKey: string): void {
    const entry = this.tunnels.get(tunnelKey);
    if (!entry) return;
    this.log(`Closing SSH tunnel ${tunnelKey}`);
    try {
      entry.server.close();
      entry.sshClient.end();
    } catch {
      // ignore errors during close
    }
    this.tunnels.delete(tunnelKey);
  }

  closeAllTunnels(): void {
    for (const key of Array.from(this.tunnels.keys())) {
      this.closeTunnel(key);
    }
  }
}

export const sshTunnelManager = new SshTunnelManager();
