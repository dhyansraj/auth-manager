import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { usePermission } from '@mcpmesh/auth-lib-react';
import { api, ApiError } from '../../api/client';
import type {
  IdentityProviderDto,
  IdentityProviderId,
  RegistrationStateDto,
} from '../../api/types';

interface Props {
  slug: string;
  /** Tenant UUID — required for the login-methods endpoints (UUID-keyed). */
  tenantId: string;
}

export default function IdentityProvidersTab({ slug, tenantId }: Props) {
  const canManage = usePermission('IDP_EDIT');
  // Password toggle is gated on TENANT_EDIT (the LoginMethodController guard).
  const canManagePassword = usePermission('TENANT_EDIT');
  const qc = useQueryClient();

  const providers = useQuery({
    queryKey: ['identity-providers', slug],
    queryFn: () => api.listIdentityProviders(slug),
    enabled: !!slug,
  });

  const loginMethods = useQuery({
    queryKey: ['login-methods', tenantId],
    queryFn: () => api.getLoginMethods(tenantId),
    enabled: !!tenantId,
  });

  const registration = useQuery({
    queryKey: ['registration-state', slug],
    queryFn: () => api.getRegistrationState(slug),
    enabled: !!slug,
  });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: IdentityProviderId; enabled: boolean }) =>
      api.setIdentityProviderEnabled(slug, id, enabled),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['identity-providers', slug] });
      // IdP toggles may affect login-methods status (e.g. last IdP gone).
      qc.invalidateQueries({ queryKey: ['login-methods', tenantId] });
    },
  });

  const togglePassword = useMutation({
    mutationFn: (enabled: boolean) => api.setPasswordEnabled(tenantId, enabled),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['login-methods', tenantId] });
    },
  });

  const toggleInviteOnly = useMutation({
    mutationFn: (inviteOnly: boolean) => api.setInviteOnly(slug, inviteOnly),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['registration-state', slug] });
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-semibold">Identity Providers</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Let your users sign in with social accounts. Toggling a provider
            adds or removes the corresponding button on this tenant&apos;s login page.
          </p>
        </div>
      </div>

      {!canManage && (
        <div className="bg-slate-50 border border-slate-200 rounded p-3 text-sm text-slate-700">
          You don&apos;t have permission to change identity providers for this tenant.
          The list below is read-only.
        </div>
      )}

      {providers.isLoading && <div>Loading…</div>}
      {providers.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          {String(providers.error)}
        </div>
      )}

      {toggle.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          {toggleErrorMessage(toggle.error)}
        </div>
      )}

      {togglePassword.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          {passwordErrorMessage(togglePassword.error)}
        </div>
      )}

      {toggleInviteOnly.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          {inviteOnlyErrorMessage(toggleInviteOnly.error)}
        </div>
      )}

      <InviteOnlyCard
        state={registration.data ?? null}
        canManage={canManage}
        busy={toggleInviteOnly.isPending}
        onToggle={(inviteOnly) => toggleInviteOnly.mutate(inviteOnly)}
      />

      {providers.data && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {providers.data.map(p => (
            <ProviderCard
              key={p.id}
              provider={p}
              canManage={canManage}
              busy={toggle.isPending && toggle.variables?.id === p.id}
              onToggle={(enabled) => toggle.mutate({ id: p.id, enabled })}
            />
          ))}
          <PasswordCard
            loginMethods={loginMethods.data ?? null}
            canManage={canManagePassword}
            busy={togglePassword.isPending}
            onToggle={(enabled) => togglePassword.mutate(enabled)}
          />
        </div>
      )}
    </div>
  );
}

function PasswordCard({
  loginMethods,
  canManage,
  busy,
  onToggle,
}: {
  loginMethods: { passwordEnabled: boolean; enabledIdpAliases: string[] } | null;
  canManage: boolean;
  busy: boolean;
  onToggle: (enabled: boolean) => void;
}) {
  const enabled = loginMethods?.passwordEnabled ?? false;
  const disabled = !canManage || busy;
  const tooltip = !canManage
    ? 'You need tenant-admin privileges to change this.'
    : undefined;

  return (
    <div className="bg-white border rounded p-4 flex items-start gap-3">
      <div className="shrink-0 mt-0.5">
        <KeycloakIcon />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex justify-between items-start gap-2">
          <div>
            <div className="font-semibold">Username / Password</div>
            <div className="text-xs text-slate-500 mt-0.5">
              Let users sign in with email and password. Disable to enforce
              social-only login (at least one identity provider must remain
              enabled).
            </div>
          </div>
          <Toggle
            checked={enabled}
            disabled={disabled || !loginMethods}
            title={tooltip}
            onChange={(next) => onToggle(next)}
          />
        </div>
      </div>
    </div>
  );
}

function InviteOnlyCard({
  state,
  canManage,
  busy,
  onToggle,
}: {
  state: RegistrationStateDto | null;
  canManage: boolean;
  busy: boolean;
  onToggle: (inviteOnly: boolean) => void;
}) {
  const enabled = state?.inviteOnly ?? false;
  const disabled = !canManage || busy || !state;
  const tooltip = !canManage
    ? 'You need tenant-admin privileges to change this.'
    : undefined;

  return (
    <div className="bg-white border rounded p-4 flex items-start gap-3">
      <div className="shrink-0 mt-0.5">
        <InviteOnlyIcon />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex justify-between items-start gap-2">
          <div>
            <div className="font-semibold">Invite-only access</div>
            <div className="text-xs text-slate-500 mt-0.5">
              When on, only users you provision or invite can sign in —
              social-login sign-ups for unknown emails are rejected, and the
              self-registration form is disabled.
            </div>
          </div>
          <Toggle
            checked={enabled}
            disabled={disabled}
            title={tooltip}
            onChange={(next) => onToggle(next)}
          />
        </div>
      </div>
    </div>
  );
}

function InviteOnlyIcon() {
  // Envelope-with-check glyph: signals "invitation required".
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="#475569"
        d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm0 2v.01L12 11l8-4.99V6H4zm0 2.24V18h16V8.24l-8 5-8-5z"
      />
    </svg>
  );
}

function inviteOnlyErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 403) {
      return 'You don’t have permission to change registration settings for this tenant.';
    }
  }
  return String(err);
}

function KeycloakIcon() {
  // Simple lock-style glyph: avoids pulling in a binary asset and keeps the
  // card visually consistent with the social provider icons.
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="#475569"
        d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5zm-3 8V7a3 3 0 1 1 6 0v3H9zm3 4a2 2 0 0 1 1 3.7V19h-2v-1.3A2 2 0 0 1 12 14z"
      />
    </svg>
  );
}

function passwordErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 400) {
      // Surface backend's canonical "no methods remaining" code.
      const m = err.message.match(/login\.no_methods_remaining[^"]*/);
      if (m) return 'Cannot disable password — at least one identity provider must remain enabled.';
    }
    if (err.status === 403) {
      return 'You don’t have permission to change login methods for this tenant.';
    }
  }
  return String(err);
}

function ProviderCard({
  provider,
  canManage,
  busy,
  onToggle,
}: {
  provider: IdentityProviderDto;
  canManage: boolean;
  busy: boolean;
  onToggle: (enabled: boolean) => void;
}) {
  const disabled = !canManage || !provider.available || busy;
  const tooltip = !provider.available
    ? 'Platform admin must configure ' + provider.displayName + ' OAuth credentials first.'
    : !canManage
      ? 'You need tenant-admin privileges to change this.'
      : undefined;

  return (
    <div
      className={
        'bg-white border rounded p-4 flex items-start gap-3 ' +
        (provider.available ? '' : 'opacity-60')
      }
    >
      <div className="shrink-0 mt-0.5">
        <ProviderIcon id={provider.id} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex justify-between items-start gap-2">
          <div>
            <div className="font-semibold">{provider.displayName}</div>
            <div className="text-xs text-slate-500 mt-0.5">
              Allow users to sign in with their {provider.displayName} account.
            </div>
          </div>
          <Toggle
            checked={provider.enabled}
            disabled={disabled}
            title={tooltip}
            onChange={(next) => onToggle(next)}
          />
        </div>
        {!provider.available && (
          <div className="mt-2 text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded px-2 py-1">
            Platform OAuth credentials are not configured. Ask the platform
            admin to register a {provider.displayName} OAuth app and run{' '}
            <code className="font-mono">setup-oauth-providers.sh</code>.
          </div>
        )}
      </div>
    </div>
  );
}

function Toggle({
  checked,
  disabled,
  title,
  onChange,
}: {
  checked: boolean;
  disabled: boolean;
  title?: string;
  onChange: (next: boolean) => void;
}) {
  return (
    <label
      className={'inline-flex items-center cursor-pointer ' + (disabled ? 'cursor-not-allowed opacity-50' : '')}
      title={title}
    >
      <input
        type="checkbox"
        className="sr-only peer"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span
        className={
          'relative w-10 h-5 rounded-full transition-colors ' +
          (checked ? 'bg-emerald-600' : 'bg-slate-300')
        }
      >
        <span
          className={
            'absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform shadow ' +
            (checked ? 'translate-x-5' : '')
          }
        />
      </span>
    </label>
  );
}

function ProviderIcon({ id }: { id: IdentityProviderId }) {
  if (id === 'google') {
    return (
      <svg width="28" height="28" viewBox="0 0 48 48" aria-hidden="true">
        <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3c-1.6 4.6-6 8-11.3 8-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z" />
        <path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.6 16.1 18.9 13 24 13c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.6 8.4 6.3 14.7z" />
        <path fill="#4CAF50" d="M24 44c5.2 0 9.8-2 13.3-5.2l-6.1-5.2c-2 1.4-4.5 2.4-7.2 2.4-5.2 0-9.7-3.4-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z" />
        <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.1 5.2C39.9 36.1 44 30.6 44 24c0-1.3-.1-2.4-.4-3.5z" />
      </svg>
    );
  }
  if (id === 'apple') {
    return (
      <svg width="28" height="28" viewBox="0 0 24 24" aria-hidden="true">
        <path
          fill="currentColor"
          d="M16.36 12.78c-.02-2.05 1.67-3.03 1.75-3.08-.95-1.4-2.44-1.59-2.97-1.61-1.26-.13-2.46.74-3.1.74-.64 0-1.63-.72-2.68-.7-1.38.02-2.65.8-3.36 2.04-1.43 2.49-.37 6.17 1.03 8.19.68.99 1.5 2.1 2.56 2.06 1.03-.04 1.42-.66 2.66-.66 1.24 0 1.59.66 2.68.64 1.11-.02 1.81-1 2.49-2 .78-1.15 1.1-2.26 1.12-2.32-.02-.01-2.16-.83-2.18-3.29zM14.5 6.55c.56-.69.94-1.64.84-2.59-.81.03-1.79.54-2.37 1.22-.52.6-.98 1.57-.86 2.5.9.07 1.83-.46 2.39-1.13z"
        />
      </svg>
    );
  }
  // github
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="#181717"
        d="M12 .3a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2.2c-3.3.7-4-1.6-4-1.6-.5-1.4-1.3-1.7-1.3-1.7-1.1-.8.1-.8.1-.8 1.2.1 1.8 1.3 1.8 1.3 1.1 1.9 2.9 1.3 3.6 1 .1-.8.4-1.3.8-1.6-2.7-.3-5.5-1.3-5.5-6 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0c2.3-1.5 3.3-1.2 3.3-1.2.6 1.7.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.6-2.8 5.7-5.5 6 .4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 12 .3z"
      />
    </svg>
  );
}

function toggleErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 422) {
      return 'Cannot enable this provider yet: platform OAuth credentials are not configured.';
    }
    if (err.status === 403) {
      return 'You don’t have permission to change identity providers for this tenant.';
    }
  }
  return String(err);
}
