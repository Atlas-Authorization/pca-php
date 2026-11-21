<?php
declare(strict_types=1);

namespace Atlas\Pca\Symfony;

use Atlas\Pca\HttpFoundationGuard;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

require_once __DIR__ . '/../HttpFoundationGuard.php';

/**
 * Symfony kernel subscriber: on every main request that `$guards` selects (default: every main request) the PCActn is verified
 * through the shared PSR-15 pipeline before the controller runs. A refusal becomes the response; a pass stores the verdict as the
 * request attribute `pca`. Runs after routing (priority 8), so `$guards` can match on the `_route` attribute.
 */
final class PcaRequestSubscriber implements EventSubscriberInterface
{
    /** @var \Closure(Request): bool */
    private readonly \Closure $guards;

    /** @param (callable(Request): bool)|null $guards */
    public function __construct(private readonly HttpFoundationGuard $guard, ?callable $guards = null)
    {
        $this->guards = $guards === null ? static fn(Request $r): bool => true : \Closure::fromCallable($guards);
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::REQUEST => ['onRequest', 8]];
    }

    public function onRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        if (!$event->isMainRequest() || ($this->guards)($request) !== true) {
            return;
        }
        [$denial, $verdict] = $this->guard->check($request);
        if ($denial !== null) {
            $event->setResponse($denial);
            return;
        }
        $request->attributes->set('pca', $verdict);
    }
}
