import { Module, forwardRef } from '@nestjs/common';
import {
  serverEnvSchema,
  NOSTR_DEFAULT_RELAYS_INJECTION_TOKEN,
  APPROVAL_CONFIG_INJECTION_TOKEN,
  type ApprovalConfig,
} from '@bunker46/config';
import { BunkerService } from './bunker.service.js';
import { BunkerGateway } from './bunker.gateway.js';
import { BunkerUriService } from './bunker-uri.service.js';
import { BunkerRpcHandler } from './bunker-rpc.handler.js';
import { ConnectionsModule } from '../connections/connections.module.js';
import { LoggingModule } from '../logging/logging.module.js';
import { EventsModule } from '../events/events.module.js';
import { EncryptionService } from '../common/crypto/encryption.service.js';
import { BunkerController } from './bunker.controller.js';
import { ApprovalService } from './approval.service.js';
import { ApprovalsController } from './approvals.controller.js';

@Module({
  imports: [forwardRef(() => ConnectionsModule), LoggingModule, EventsModule],
  providers: [
    {
      provide: NOSTR_DEFAULT_RELAYS_INJECTION_TOKEN,
      useFactory: () => serverEnvSchema.parse(process.env).NOSTR_DEFAULT_RELAYS,
    },
    {
      provide: APPROVAL_CONFIG_INJECTION_TOKEN,
      useFactory: (): ApprovalConfig => {
        const env = serverEnvSchema.parse(process.env);
        return { ttlMs: env.ASK_APPROVAL_TTL_MS, publicBaseUrl: env.PUBLIC_BASE_URL };
      },
    },
    ApprovalService,
    BunkerService,
    BunkerGateway,
    BunkerUriService,
    BunkerRpcHandler,
    EncryptionService,
  ],
  controllers: [BunkerController, ApprovalsController],
  exports: [BunkerService, ApprovalService],
})
export class BunkerModule {}
