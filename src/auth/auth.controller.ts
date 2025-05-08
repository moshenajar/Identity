import { Body, Controller, Get, HttpException, HttpStatus, Post, Put, Req, UnauthorizedException, UseGuards } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthCredentialsDto } from "./dtos/auth.credentials.dto";
import { AuthGuard } from "@nestjs/passport";
import { GetUser } from "./get-user.decorator";
import { User } from "./entities/user.entity";
import { RefreshTokenDto } from "./dtos/refresh-tokens.dto";
import { ChangePasswordDto } from "./dtos/change-password.dto";
import { ResetPasswordDto } from "./dtos/reset-password.dto";
import { ForgotPasswordDto } from "./dtos/forgot-password.dto";
import { AuthenticationGuard } from "./guards/authentication.guard";
import { LoginDto } from "./dtos/login.dto";

import { MessagePattern, Payload } from '@nestjs/microservices';
import { response } from "express";
import { UtilsService } from "./utils/utils-service";
import { ForgotPasswordOtpDto } from "./dtos/forgot-password-otp.dto";

@Controller('auth')
export class AuthController {
    constructor(
        private authService: AuthService,
        private utilsService: UtilsService,
    ) { }

    @MessagePattern('login')
    async signIn(loginDto: LoginDto) {
        return this.authService.login(loginDto);
    }

    @MessagePattern('signup')
    async signUp(authCredentialsDto: AuthCredentialsDto) {
        return this.authService.signUp(authCredentialsDto);
    }


    @MessagePattern('refreshToken')
    async refreshToken(user:User) {
        return this.authService.refreshToken(user);
    }

    @MessagePattern('validateToken')
    async validateToken(accessToken: string) {
        return await this.authService.validateToken(accessToken);
    }

    @MessagePattern('validateRefreshToken')
    async validateRefreshToken(accessToken: string) {
        return await this.authService.validateRefreshToken(accessToken);
    }

    @MessagePattern('changePassword')
    async changePassword(data: { userId: string, changePasswordDto: ChangePasswordDto }) {
        return this.authService.changePassword(
            data.userId,
            data.changePasswordDto.oldPassword,
            data.changePasswordDto.newPassword,
        );
    }

    @MessagePattern('forgotPasswordOtp')
    async forgotPasswordOtp(data: { forgotPasswordOtpDto: ForgotPasswordOtpDto }) {
        return this.authService.forgotPasswordOtp(data.forgotPasswordOtpDto);
    }

    @MessagePattern('forgotPassword')
    async forgotPassword(data: { forgotPasswordDto: ForgotPasswordDto }) {
        return this.authService.forgotPassword(data.forgotPasswordDto);
    }

    @MessagePattern('resetPassword')
    async resetPassword(data: { resetPasswordDto: ResetPasswordDto }) {
        return this.authService.resetPassword(data.resetPasswordDto);
    }

    @MessagePattern('getUserByUserId')
    async getUserByUserId(data: { userId: string }) {
        return this.authService.getUserByUserId(data.userId);
    }


    @Post('/getUser')
    @UseGuards(AuthGuard())
    getUser(@GetUser() user: User) {
        console.log(user);
    }

    @MessagePattern('test')
    async test(data: { hi: string }) {
        console.log(data.hi);
        return "by";
    }



    /*@Post('signup')
    async signUp(@Body() authCredentialsDto: AuthCredentialsDto): Promise<void> {
        return this.authService.signUp(authCredentialsDto);
    }*/

    /* @Post('login')
     async signIn(@Body() loginDto: LoginDto) {
         return this.authService.login(loginDto);
     }*/

    /*@Post('refresh')
    async refreshTokens(@Body() refreshTokenDto: RefreshTokenDto) {
        return this.authService.refreshTokens(refreshTokenDto.refreshToken);
    }*/

    /*  @UseGuards(AuthenticationGuard)
      @Put('change-password')
      async changePassword(
          @Body() changePasswordDto: ChangePasswordDto,
          @Req() req,
      ) {
          return this.authService.changePassword(
              req.userId,
              changePasswordDto.oldPassword,
              changePasswordDto.newPassword,
          );
      }*/

    /*@Post('forgot-password')
    async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
        return this.authService.forgotPassword(forgotPasswordDto.email);
    }*/

    /*@Put('reset-password')
    async resetPassword(
        @Body() resetPasswordDto: ResetPasswordDto,
    ) {
        return this.authService.resetPassword(
            resetPasswordDto.newPassword,
            resetPasswordDto.resetToken,
        );
    }*/

    /*@Post('/getUser')
    @UseGuards(AuthGuard())
    getUser(@GetUser() user: User) {
        console.log(user);
    }*/

    /*@Post('/validateToken')
    @UseGuards(AuthGuard())
    validateToken(@GetUser() user: User) {
        return user;
    }*/



}