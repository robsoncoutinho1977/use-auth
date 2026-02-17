import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const corsOrigins = (configService.get<string>('CORS_ORIGINS') ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
  const corsBaseDomain = configService.get<string>('CORS_BASE_DOMAIN') ?? '';

  app.enableCors({
    credentials: true,
    origin: (origin, callback) => {
      if (!origin) {
        callback(null, true);
        return;
      }

      if (corsOrigins.includes(origin)) {
        callback(null, true);
        return;
      }

      if (corsBaseDomain && origin.endsWith(`.${corsBaseDomain}`)) {
        callback(null, true);
        return;
      }

      callback(new Error('CORS origin not allowed'), false);
    },
  });
  const appPortRaw = configService.get<string>('APP_PORT') ?? '3001';
  const appPort = Number(appPortRaw);
  await app.listen(Number.isFinite(appPort) ? appPort : 3001);
}
bootstrap();
