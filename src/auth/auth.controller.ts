import { Body, Controller, Get, Post, Req, UseGuards } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthCredentialsDto } from "./dto/auth.credentials.dto";
import { AuthGuard } from "@nestjs/passport";
import { GetUser } from "./get-user.decorator";
import { User } from "./user.entity";
//import { User } from "./get-user.decorator";

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService){}

    @Post('/signup')
    signUp(@Body() authCredentialsDto: AuthCredentialsDto): Promise<void> {
        return this.authService.signUp(authCredentialsDto);
    }

    @Post('/signin')
    signIn(@Body() authCredentialsDto: AuthCredentialsDto): Promise<{ accessToken: string }> {
        return this.authService.signIn(authCredentialsDto);
    }
/*
    @Post('/test')
    @UseGuards(AuthGuard())
    test(@User() user) {
        console.log(user);
    }

    */

    @Post('/getUser')
    @UseGuards(AuthGuard())
    getUser(@GetUser() user: User) {
        console.log(user);
    }

    @Post('/validateToken')
    @UseGuards(AuthGuard())
    validateToken(@GetUser() user: User) {
       return user;
    }

    @Get('/moshe')
    moshe() {
        return "moshe";
    }
}