import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      // Remove properties that are not in the DTO
      whitelist: true,
      // Throw an error if a property that is not in the DTO is sent
      forbidNonWhitelisted: true,
      // Transform the request body to the DTO type
      transform: true,
    }),
  );
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
