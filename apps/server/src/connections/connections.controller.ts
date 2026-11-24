import {
  BadRequestException,
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Patch,
  Body,
  Param,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
  Inject,
  forwardRef,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { TotpVerifiedGuard } from '../auth/guards/totp-verified.guard.js';
import { ConnectionsService } from './connections.service.js';
import { BunkerService } from '../bunker/bunker.service.js';
import { ApprovalService } from '../bunker/approval.service.js';
import {
  ApprovalModeSchema,
  PermissionListSchema,
  SafeRelayUrlsSchema,
  SetApprovalModeBodySchema,
  type ApprovalMode,
  type PermissionDescriptor,
} from '@bunker46/shared-types';
import type { FastifyRequest } from 'fastify';

type AuthReq = FastifyRequest & { user: { sub: string } };

@ApiTags('connections')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, TotpVerifiedGuard)
@Controller('api/connections')
export class ConnectionsController {
  constructor(
    private readonly connectionsService: ConnectionsService,
    @Inject(forwardRef(() => BunkerService))
    private readonly bunkerService: BunkerService,
    @Inject(forwardRef(() => ApprovalService))
    private readonly approvals: ApprovalService,
  ) {}

  @Get()
  async list(@Req() req: AuthReq) {
    return this.connectionsService.listConnections(req.user.sub);
  }

  @Get('nsec-keys')
  async listNsecKeys(@Req() req: AuthReq) {
    return this.connectionsService.getNsecKeys(req.user.sub);
  }

  @Post('nsec-keys')
  async addNsecKey(
    @Req() req: AuthReq,
    @Body() body: { nsecHex: string; publicKey: string; label?: string },
  ) {
    return this.connectionsService.addNsecKey(
      req.user.sub,
      body.nsecHex,
      body.publicKey,
      body.label ?? 'Default Key',
    );
  }

  @Patch('nsec-keys/:keyId')
  async updateNsecKeyLabel(
    @Req() req: AuthReq,
    @Param('keyId') keyId: string,
    @Body() body: { label: string },
  ) {
    const label = (body.label ?? '').trim();
    if (!label || label.length > 100) {
      throw new BadRequestException('Label must be between 1 and 100 characters');
    }
    return this.connectionsService.updateNsecKeyLabel(keyId, req.user.sub, label);
  }

  @Delete('nsec-keys/:keyId')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteNsecKey(@Req() req: AuthReq, @Param('keyId') keyId: string) {
    await this.connectionsService.deleteNsecKey(keyId, req.user.sub);
  }

  @Get(':id')
  async get(@Req() req: AuthReq, @Param('id') id: string) {
    return this.connectionsService.getConnection(id, req.user.sub);
  }

  @Post()
  async create(
    @Req() req: AuthReq,
    @Body()
    body: {
      nsecKeyId: string;
      clientPubkey: string;
      name?: string;
      logoUrl?: string;
      relays?: string[];
      secret?: string;
      remotePubkey?: string;
      /** The permissions to GRANT, as picked by the operator. Absent: the conservative defaults. */
      permissions?: unknown;
      /** Removed: the old comma-separated string. Refused rather than ignored, see below. */
      perms?: unknown;
      /** DENY (default) or ASK: what happens to a gated request the connection holds no permission for. */
      approvalMode?: unknown;
      type?: 'nostrconnect' | 'bunker';
    },
  ) {
    let validatedRelays: string[] | undefined;
    if (body.relays != null && body.relays.length > 0) {
      const parsed = SafeRelayUrlsSchema.safeParse(body.relays);
      if (!parsed.success) {
        throw new BadRequestException(
          parsed.error.flatten().formErrors.join(' ') || 'Invalid relay URLs',
        );
      }
      validatedRelays = parsed.data;
    }

    // The old `perms` string used to be applied here, and any parse error was swallowed. A caller that
    // still sends it would now get the default permissions without a word, so it is an error instead.
    if (body.perms !== undefined) {
      throw new BadRequestException('perms is no longer accepted: send permissions as a list');
    }

    // Validated, not parsed leniently: a list that does not validate is an error the caller sees, not
    // a connection quietly created with other permissions than the operator chose. An empty list is a
    // choice (the connection starts able to do nothing); only an absent one means the defaults.
    let permissions: PermissionDescriptor[] | undefined;
    if (body.permissions !== undefined) {
      const parsedPerms = PermissionListSchema.safeParse(body.permissions);
      if (!parsedPerms.success) throw new BadRequestException('Invalid permissions list');
      permissions = parsedPerms.data;
    }
    let approvalMode: ApprovalMode | undefined;
    if (body.approvalMode !== undefined) {
      const parsedMode = ApprovalModeSchema.safeParse(body.approvalMode);
      if (!parsedMode.success) throw new BadRequestException('approvalMode must be DENY or ASK');
      approvalMode = parsedMode.data;
    }

    const conn = await this.connectionsService.createConnection(
      req.user.sub,
      body.nsecKeyId,
      body.clientPubkey,
      {
        name: body.name,
        logoUrl: body.logoUrl,
        relays: validatedRelays ?? body.relays,
        secret: body.secret,
        remotePubkey: body.remotePubkey,
        approvalMode,
      },
      permissions,
    );

    await this.bunkerService.ensureListeningForConnection(
      body.nsecKeyId,
      req.user.sub,
      validatedRelays ?? body.relays ?? [],
    );

    if (body.type === 'nostrconnect' && body.secret) {
      await this.bunkerService.sendConnectResponse(
        body.nsecKeyId,
        req.user.sub,
        body.clientPubkey,
        body.secret,
        validatedRelays ?? body.relays ?? [],
      );
      await this.connectionsService.updateConnectionStatus(conn.id, 'ACTIVE');
    }

    return this.connectionsService.getConnection(conn.id, req.user.sub);
  }

  @Put(':id/permissions')
  async setPermissions(
    @Req() req: AuthReq,
    @Param('id') id: string,
    @Body() body: { permissions?: unknown },
  ) {
    // Validated like every other way in: an unchecked kind that does not fit the database is a 500.
    const parsed = PermissionListSchema.safeParse(body?.permissions);
    if (!parsed.success) throw new BadRequestException('Invalid permissions list');
    await this.connectionsService.getConnection(id, req.user.sub);
    await this.connectionsService.setPermissions(id, parsed.data);
    return { success: true };
  }

  // Approve client-requested (pending) permissions; omit `permissions` to approve all pending.
  @Post(':id/permissions/approve')
  @HttpCode(HttpStatus.OK)
  async approvePermissionRequests(
    @Req() req: AuthReq,
    @Param('id') id: string,
    @Body() body: { permissions?: PermissionDescriptor[] },
  ) {
    await this.connectionsService.approveRequests(id, req.user.sub, body?.permissions);
    return { success: true };
  }

  // Deny (delete) client-requested (pending) permissions; omit `permissions` to deny all pending.
  @Post(':id/permissions/deny')
  @HttpCode(HttpStatus.OK)
  async denyPermissionRequests(
    @Req() req: AuthReq,
    @Param('id') id: string,
    @Body() body: { permissions?: PermissionDescriptor[] },
  ) {
    await this.connectionsService.denyRequests(id, req.user.sub, body?.permissions);
    return { success: true };
  }

  @Patch(':id/status')
  async updateStatus(
    @Req() req: AuthReq,
    @Param('id') id: string,
    @Body() body: { status: 'ACTIVE' | 'REVOKED' },
  ) {
    await this.connectionsService.getConnection(id, req.user.sub);
    const updated = await this.connectionsService.updateConnectionStatus(id, body.status);
    // A revoked connection must not sign what it was holding: end the waits, so the clients get
    // their answer now instead of when the hold times out.
    if (body.status === 'REVOKED') this.approvals.cancelForConnection(id);
    return updated;
  }

  @Patch(':id/approval-mode')
  async setApprovalMode(@Req() req: AuthReq, @Param('id') id: string, @Body() body: unknown) {
    const parsed = SetApprovalModeBodySchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException('mode must be DENY or ASK');
    const updated = await this.connectionsService.setApprovalMode(
      id,
      req.user.sub,
      parsed.data.mode,
    );
    // Back to DENY: whatever is being held is answered (as denied) now.
    if (parsed.data.mode === 'DENY') this.approvals.cancelForConnection(id);
    return updated;
  }

  @Patch(':id/logging')
  async toggleLogging(
    @Req() req: AuthReq,
    @Param('id') id: string,
    @Body() body: { enabled: boolean },
  ) {
    return this.connectionsService.toggleLogging(id, req.user.sub, body.enabled);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Req() req: AuthReq, @Param('id') id: string) {
    await this.connectionsService.deleteConnection(id, req.user.sub);
    this.approvals.cancelForConnection(id);
  }
}
