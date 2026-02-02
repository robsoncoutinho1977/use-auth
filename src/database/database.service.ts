import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createPool, Pool } from 'mysql2/promise';
import type { EnvVars } from '../config/env.schema';

@Injectable()
export class DatabaseService implements OnModuleDestroy {
  private readonly logger = new Logger(DatabaseService.name);
  private readonly pool: Pool;

  constructor(private readonly configService: ConfigService<EnvVars, true>) {
    const host = this.configService.getOrThrow<string>('DB_HOST');
    const user = this.configService.getOrThrow<string>('DB_USER');
    const password = this.configService.getOrThrow<string>('DB_PASSWORD');
    const database = this.configService.getOrThrow<string>('DB_NAME');
    const port = Number(this.configService.get<string>('DB_PORT') ?? 3306);
    const connectionLimit = Number(
      this.configService.get<string>('DB_CONNECTION_LIMIT') ?? 5,
    );

    this.pool = createPool({
      host,
      user,
      password,
      database,
      port,
      waitForConnections: true,
      connectionLimit,
      queueLimit: 0,
    });
  }

  async query<T = unknown>(sql: string, params?: unknown[]): Promise<T[]> {
    const [rows] = await this.pool.query(sql, params ?? []);
    return rows as T[];
  }

  async onModuleDestroy(): Promise<void> {
    try {
      await this.pool.end();
    } catch (error) {
      this.logger.error('Failed to close MySQL pool', error as Error);
    }
  }
}
