import { useEffect, useState } from 'react';

interface Props {
  isOpen: boolean;
  title: string;
  description?: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Red confirm button for destructive actions. */
  danger?: boolean;
  /** When set, the user must type this exact text to enable the confirm button. */
  requireText?: string;
  isLoading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Reusable controlled confirm modal. Replaces window.confirm() across the
 * admin UI. Follows the existing modal conventions (backdrop click to
 * dismiss, stopPropagation on the box, slate/red action buttons).
 */
export default function ConfirmDialog({
  isOpen,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  danger = false,
  requireText,
  isLoading = false,
  onConfirm,
  onCancel,
}: Props) {
  const [typed, setTyped] = useState('');

  // Reset the type-to-confirm input each time the dialog opens.
  useEffect(() => {
    if (isOpen) setTyped('');
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, onCancel]);

  if (!isOpen) return null;

  const confirmDisabled =
    isLoading || (requireText !== undefined && typed !== requireText);

  const confirmClass = danger
    ? 'bg-red-600 text-white px-3 py-1 rounded text-sm hover:bg-red-700 disabled:opacity-50'
    : 'bg-slate-900 text-white px-3 py-1 rounded text-sm hover:bg-slate-700 disabled:opacity-50';

  return (
    <div
      className="fixed inset-0 z-50 bg-black/30 flex items-start justify-center p-6 overflow-y-auto"
      onClick={onCancel}
    >
      <div
        className="bg-white rounded shadow-lg w-full max-w-md p-5 space-y-3 mt-12"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <h3 className="text-lg font-semibold">{title}</h3>
        {description && (
          <div className="text-sm text-slate-600">{description}</div>
        )}
        {requireText !== undefined && (
          <div className="space-y-1">
            <label className="block text-sm text-slate-600">
              Type <code className="font-mono text-xs bg-slate-100 px-1 py-0.5 rounded">{requireText}</code> to confirm
            </label>
            <input
              autoFocus
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              disabled={isLoading}
              className="border rounded px-2 py-1 text-sm font-mono w-full"
            />
          </div>
        )}
        <div className="flex gap-2 justify-end pt-2 border-t">
          <button
            type="button"
            onClick={onCancel}
            disabled={isLoading}
            className="text-sm text-slate-600 hover:text-slate-900 px-3 py-1 disabled:opacity-50"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={confirmDisabled}
            className={confirmClass}
          >
            {isLoading ? `${confirmLabel}…` : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
