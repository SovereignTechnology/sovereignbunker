import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { ApproveApprovalBodySchema, type PermissionDescriptor } from '@bunker46/shared-types';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { TotpVerifiedGuard } from '../auth/guards/totp-verified.guard.js';
import { ConnectionsService } from '../connections/connections.service.js';
import { ApprovalService } from './approval.service.js';

type AuthReq = FastifyRequest & { user: { sub: string } };

/** A token is base64url of 24 random bytes; anything else cannot match and is refused up front. */
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{16,64}$/;

// Both named throttlers apply to every route, so both are set. Reads are polled by the app header
// (about 12 a minute at the 5 s fallback); decisions are rare, so they get a much lower ceiling.
const READ_LIMIT = { default: { limit: 120, ttl: 60_000 }, auth: { limit: 120, ttl: 60_000 } };
const DECIDE_LIMIT = { default: { limit: 30, ttl: 60_000 }, auth: { limit: 30, ttl: 60_000 } };

/**
 * The operator's side of hold-and-ask: see the requests being held and decide them. The link a
 * client is sent (`<PUBLIC_BASE_URL>/approvals/<token>`) opens a page of the web app behind the
 * normal login (JWT, and TOTP when enabled); it is never a bearer link. Every route here is scoped
 * to the logged-in user, and a token that is unknown, already decided, or another user's is one and
 * the same 404.
 */
@ApiTags('approvals')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, TotpVerifiedGuard)
@Controller('api/approvals')
export class ApprovalsController {
  constructor(
    private readonly approvals: ApprovalService,
    private readonly connections: ConnectionsService,
  ) {}

  @Get()
  @Throttle(READ_LIMIT)
  list(@Req() req: AuthReq) {
    return { approvals: this.approvals.list(req.user.sub) };
  }

  @Get(':token')
  @Throttle(READ_LIMIT)
  get(@Req() req: AuthReq, @Param('token') token: string) {
    return this.approvals.get(this.checkedToken(token), req.user.sub);
  }

  /**
   * `once` answers this request only. `always` also grants the permission to the connection (so the
   * client is not asked again for that method and kind), then answers.
   */
  @Post(':token/approve')
  @HttpCode(HttpStatus.OK)
  @Throttle(DECIDE_LIMIT)
  async approve(@Req() req: AuthReq, @Param('token') token: string, @Body() body: unknown) {
    const parsed = ApproveApprovalBodySchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException('mode must be "once" or "always"');
    }
    const userId = req.user.sub;
    const held = this.approvals.get(this.checkedToken(token), userId);

    if (parsed.data.mode === 'always') {
      // Granted before the hold is settled: the request is handled again after the wait and must
      // find the permission already there. Owner-checked inside.
      await this.connections.grantPermissions(held.connectionId, userId, [
        { method: held.method as PermissionDescriptor['method'], kind: held.kind },
      ]);
    }
    try {
      this.approvals.resolve(
        token,
        userId,
        parsed.data.mode === 'always' ? 'approved_always' : 'approved_once',
      );
    } catch (err) {
      // The wait ended (timed out, or the connection was revoked) between the check above and now.
      // For "always" the grant is already stored, which is what the operator asked for, so say so
      // instead of reporting a failure; for "once" there is nothing left to allow.
      if (!(err instanceof NotFoundException) || parsed.data.mode !== 'always') throw err;
      return { success: true };
    }
    return { success: true };
  }

  /** Refuse the request; the pending permission row it filed is removed too. */
  @Post(':token/deny')
  @HttpCode(HttpStatus.OK)
  @Throttle(DECIDE_LIMIT)
  async deny(@Req() req: AuthReq, @Param('token') token: string) {
    const userId = req.user.sub;
    const held = this.approvals.get(this.checkedToken(token), userId);
    await this.connections.denyRequests(held.connectionId, userId, [
      { method: held.method as PermissionDescriptor['method'], kind: held.kind },
    ]);
    this.approvals.resolve(token, userId, 'denied');
    return { success: true };
  }

  private checkedToken(token: string): string {
    // Not a distinct error: a malformed token reads as one that does not exist.
    if (!TOKEN_SHAPE.test(token)) throw new BadRequestException('Invalid approval token');
    return token;
  }
}
