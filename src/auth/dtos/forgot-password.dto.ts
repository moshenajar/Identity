import { IsEmail, IsString } from 'class-validator';

export class ForgotPasswordDto {
  @IsString()
    userId: string;

    @IsString()
    originalOtp: string;

    @IsString()
    otp: string;
}