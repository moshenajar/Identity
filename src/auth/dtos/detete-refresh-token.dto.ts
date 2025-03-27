import { IsDate, IsString } from 'class-validator';

export class DeleteRefreshTokenDto {
  @IsString()
  refreshToken: string;
  @IsDate()
  expiryDate: Date;
}