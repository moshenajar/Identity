import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';
import { Logger, ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const logger = new Logger('main');
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  //const REDIS_HOST = configService.get<string>('REDIS_HOST');
  //const REDIS_PORT = configService.get<number>('REDIS_PORT');
  const microserviceOptions = {
    /*transport: Transport.REDIS,
    options: {
      url: `redis://${REDIS_HOST}:${REDIS_PORT}`,
    },*/
  };
  app.connectMicroservice(microserviceOptions);
  app.useGlobalPipes(new ValidationPipe());
  const port = configService.get<number>('port');
  const environment = configService.get<string>('node_env');
  const title = configService.get<string>('environment_title');
  await app.listen(port);
  logger.log(
    `${environment}, Microservice ready to receive Redis messages in PORT - ${port}\n Environment - ${title}`,
  );

  //const app = await NestFactory.createMicroservice<MicroserviceOptions>(
  //  AppModule,
    //{
    //  transport: Transport.RMQ,
    //  options: {
    //    urls: ['amqp://localhost:5672'],
    //    queue: 'inventory-queue',
    //  },
    //},
  //);
  //const configService = app.get(ConfigService);
  //const PORT = configService.get<number>(process.env.PORT ?? '3000');
  //await app.listen();
  //const app = await NestFactory.create(AppModule);
  //await app.listen(process.env.PORT ?? 3000);
  //await app.listen(PORT);
}
bootstrap();
