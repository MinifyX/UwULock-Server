import { useToast } from '../lib/toast';

/**
 * The toast at the bottom, in two live regions that are always there: screen readers only read
 * out what changes inside a region they already know, not a region that appears with its text.
 * Notes are polite; errors interrupt.
 */
export function Toasts() {
  const current = useToast();
  const info = current?.tone === 'info' ? current : null;
  const error = current?.tone === 'error' ? current : null;
  return (
    <>
      <div role="status" aria-live="polite" aria-atomic="true">
        {info && (
          <div className="toast" data-tone="info" key={info.id}>
            {info.text}
          </div>
        )}
      </div>
      <div role="alert" aria-live="assertive" aria-atomic="true">
        {error && (
          <div className="toast" data-tone="error" key={error.id}>
            {error.text}
          </div>
        )}
      </div>
    </>
  );
}
