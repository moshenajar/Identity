import { Injectable } from '@nestjs/common';
import { ApiResponseDto } from '../dtos/api-response.dto';

@Injectable()
export class UtilsService {

    constructor() {}

    apiResponse<T>(statusCode: number, data: any = null, messages: {message:string,property:string}[] | [] = []): ApiResponseDto<T> {
        return {
          statusCode,
          messages,
          data,
        };
      }

}