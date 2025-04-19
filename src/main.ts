import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';
import { Logger, ValidationPipe } from '@nestjs/common';

/*async function bootstrap() {
  const logger = new Logger('main');
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);*/
  //const microserviceOptions = {
    /*transport: Transport.REDIS,
    options: {
      url: `redis://${REDIS_HOST}:${REDIS_PORT}`,
    },*/
  //};
  /*app.connectMicroservice(microserviceOptions);
  app.useGlobalPipes(new ValidationPipe());
  const port = configService.get<number>('port');
  const environment = configService.get<string>('node_env');
  const title = configService.get<string>('environment_title');
  await app.listen(port);
  logger.log(
    `${environment}, Microservice ready to receive Redis messages in PORT - ${port}\n Environment - ${title}`,
  );

}
bootstrap();*/

const logger = new Logger('Main')

const microServiceOptions = {
  transport: Transport.TCP,
  options: {
    host: '127.0.0.1',
    port : 8123
  }
}

async function bootstrap() {

  const app = await NestFactory.createMicroservice(AppModule, microServiceOptions)

  app.listen()
  
}
bootstrap();
