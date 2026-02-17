import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import * as cookie from 'cookie';
import * as jwt from 'jsonwebtoken';
import { DatabaseService } from '../database/database.service';
import type { EnvVars } from '../config/env.schema';
import type { AuthUserPayload, AuthUserRow } from './auth.types';
import type { Response, Request } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private readonly configService: ConfigService<EnvVars, true>,
    private readonly databaseService: DatabaseService,
  ) {}

  async validateLogin(login: string, senha: string): Promise<AuthUserPayload> {
    const rows = await this.databaseService.query<AuthUserRow>(
      `SELECT id,
              idtipousuario,
              idcentro,
              centro,
              nomefantasia,
              idtipousuariocentro,
              nomerazao,
              cpfcnpj,
              login,
              email,
              idstatususuario,
              senha
         FROM vUsuarios
        WHERE login = ?
        LIMIT 1`,
      [login],
    );

    if (rows.length === 0) {
      throw new UnauthorizedException('Credenciais invalidas');
    }

    const usuario = rows[0];
    const senhaHash = usuario.senha ?? '';
    const senhaConfere = await bcrypt.compare(senha, senhaHash);

    if (!senhaConfere) {
      throw new UnauthorizedException('Credenciais invalidas');
    }

    const { senha: senhaDb, ...payload } = usuario;
    void senhaDb;
    return payload;
  }

  createAccessToken(payload: AuthUserPayload): string {
    const secret = this.configService.getOrThrow<string>('JWT_SECRET');
    const expiresIn = (this.configService.get<string>('JWT_EXPIRES_IN') ??
      '2h') as jwt.SignOptions['expiresIn'];
    return jwt.sign(payload as jwt.JwtPayload, secret, { expiresIn });
  }

  parseTokenFromRequest(req: Request): string | null {
    const cookieName = this.getCookieName();
    const rawCookie = req.headers.cookie;
    if (!rawCookie) {
      return null;
    }

    const parsed = cookie.parse(rawCookie);
    const token = parsed[cookieName];
    return token ?? null;
  }

  verifyAccessToken(token: string): AuthUserPayload {
    const secret = this.configService.getOrThrow<string>('JWT_SECRET');
    return jwt.verify(token, secret) as AuthUserPayload;
  }

  setAuthCookie(res: Response, token: string): void {
    res.cookie(this.getCookieName(), token, this.getCookieOptions());
  }

  clearAuthCookie(res: Response): void {
    res.clearCookie(this.getCookieName(), this.getCookieOptions());
  }

  private getCookieName(): string {
    return this.configService.get<string>('COOKIE_NAME') ?? 'use_auth';
  }

  private getCookieOptions(): {
    httpOnly: boolean;
    secure: boolean;
    sameSite: 'lax' | 'strict' | 'none';
    domain?: string;
    path: string;
    maxAge?: number;
  } {
    const domain = (
      this.configService.get<string>('COOKIE_DOMAIN') ?? ''
    ).trim();
    const secure =
      (
        this.configService.get<string>('COOKIE_SECURE') ?? 'false'
      ).toLowerCase() === 'true';
    const sameSiteRaw = (
      this.configService.get<string>('COOKIE_SAMESITE') ?? 'lax'
    ).toLowerCase();
    const sameSite =
      sameSiteRaw === 'none' || sameSiteRaw === 'strict' ? sameSiteRaw : 'lax';

    const maxAgeSeconds = this.parseJwtMaxAgeSeconds();

    return {
      httpOnly: true,
      secure,
      sameSite,
      path: '/',
      ...(domain ? { domain } : {}),
      ...(maxAgeSeconds ? { maxAge: maxAgeSeconds * 1000 } : {}),
    };
  }

  private parseJwtMaxAgeSeconds(): number | null {
    const expiresIn = this.configService.get<string>('JWT_EXPIRES_IN');
    if (!expiresIn) {
      return null;
    }

    const match = expiresIn.match(/^(\d+)([smhd])$/i);
    if (!match) {
      return null;
    }

    const value = Number(match[1]);
    const unit = match[2].toLowerCase();
    const multipliers: Record<string, number> = {
      s: 1,
      m: 60,
      h: 60 * 60,
      d: 24 * 60 * 60,
    };

    return value * (multipliers[unit] ?? 0);
  }
}
