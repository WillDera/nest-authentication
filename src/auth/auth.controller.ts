import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto';
import { RegisterDto } from './dto/register.dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto): Promise<Tokens> {
    return this.authService.register(dto);
  }

  @Post('login')
  login(@Body() dto: LoginDto): Promise<Tokens> {
    return this.authService.login(dto);
  }

  @Post('logout')
  logout() {
    return this.authService.logout();
  }

  @Post('refresh')
  refreshTokens() {
    return this.authService.refreshTokens();
  }
}
