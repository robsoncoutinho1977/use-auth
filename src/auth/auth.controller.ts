import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(
    @Body() body: { login?: string; senha?: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    const login = body.login?.trim();
    const senha = body.senha ?? '';

    if (!login || !senha) {
      throw new UnauthorizedException('Credenciais invalidas');
    }

    const user = await this.authService.validateLogin(login, senha);
    const token = this.authService.createAccessToken(user);
    this.authService.setAuthCookie(res, token);

    return { user };
  }

  @Post('logout')
  logout(@Res({ passthrough: true }) res: Response) {
    this.authService.clearAuthCookie(res);
    return { ok: true };
  }

  @Get('me')
  me(@Req() req: Request) {
    const token = this.authService.parseTokenFromRequest(req);
    if (!token) {
      throw new UnauthorizedException('Sessao invalida');
    }

    const user = this.authService.verifyAccessToken(token);
    return { user };
  }
}
