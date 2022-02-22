import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { LoginDto, RegisterDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { env } from 'process';
import { LoginUsernameDto } from './dto/loginUser.dto';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async register(dto: RegisterDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password);

    const newUser = await this.prisma.user.create({
      data: {
        email: dto.email,
        username: dto.username,
        phone_number: dto.phone_number,
        hash,
      },
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRtHash(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async updateRtHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }

  async login(dto: LoginDto): Promise<Tokens> {
    if (dto.email) {
      const user = await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      });

      if (!user) throw new ForbiddenException('Access Denied');

      const passwordMatches = await bcrypt.compare(dto.password, user.hash);
      if (!passwordMatches) throw new ForbiddenException('Access Denied');

      const tokens = await this.getTokens(user.id, user.email);
      await this.updateRtHash(user.id, tokens.refresh_token);
      return tokens;
    } else {
      const user = await this.prisma.user.findUnique({
        where: {
          username: dto.username,
        },
      });

      if (!user) throw new ForbiddenException('Access Denied');

      const passwordMatches = await bcrypt.compare(dto.password, user.hash);
      if (!passwordMatches) throw new ForbiddenException('Access Denied');

      const tokens = await this.getTokens(user.id, user.username);
      await this.updateRtHash(user.id, tokens.refresh_token);
      return tokens;
    }
  }

  logout() {}
  refreshTokens() {}

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  async getTokens(userId: number, email: string) {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: env.AT_SECRET,
          expiresIn: 60 * 10,
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: env.RT_SECRET,
          expiresIn: 60 * 60 * 24 * 7,
        },
      ),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }
}
