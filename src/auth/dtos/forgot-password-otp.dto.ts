import { IsString } from "class-validator";

export class ForgotPasswordOtpDto {
    @IsString()
    userName: string;

    @IsString()
    phone: string;

}