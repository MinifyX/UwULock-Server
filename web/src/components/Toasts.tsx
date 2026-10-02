import { useToast, type Toast } from '../lib/toast';
import { Nyu } from './nyu/Nyu';

/**
 * A small Nyu at the start of a toast: sad for an error, starry-eyed when something worked or was
 * copied (those notes end in ✧), otherwise just happy. She hops in once; with animations off she
 * simply sits there. Decoration only: screen readers hear the text.
 */
function ToastNyu({ toast }: { toast: Toast }) {
  const mood = toast.tone === 'error' ? 'sad' : toast.text.includes('✧') ? 'sparkle' : 'happy';
  return (
    <span className="toast-nyu nyu-pop">
      <Nyu size={22} mood={mood} blink={false} title="" />
    </span>
  );
}

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
            <ToastNyu toast={info} />
            <span>{info.text}</span>
          </div>
        )}
      </div>
      <div role="alert" aria-live="assertive" aria-atomic="true">
        {error && (
          <div className="toast" data-tone="error" key={error.id}>
            <ToastNyu toast={error} />
            <span>{error.text}</span>
          </div>
        )}
      </div>
    </>
  );
}
