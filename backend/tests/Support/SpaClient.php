<?php

namespace Tests\Support;

use Illuminate\Support\Facades\Auth;
use Illuminate\Testing\TestResponse;
use Tests\TestCase;

/**
 * One browser: its own cookies, origin and address, using the real cookie encryption and CSRF flow.
 * Everything cached in memory is cleared before each request, so a request only knows what its
 * cookies and the session store say, as it would in production.
 */
final class SpaClient
{
    /** @var array<string, string> */
    private array $cookies = [];

    public function __construct(
        private readonly TestCase $test,
        public ?string $origin = 'http://localhost:8080',
        public string $ip = '203.0.113.10',
    ) {}

    public function csrf(): self
    {
        $this->send('GET', '/sanctum/csrf-cookie');

        return $this;
    }

    /**
     * @param  array<array-key, mixed>|null  $json
     * @param  array<string, string>  $server
     */
    public function send(string $method, string $uri, ?array $json = null, array $server = []): TestResponse
    {
        Auth::forgetGuards();
        app('session')->driver()->flush();

        $headers = ['HTTP_ACCEPT' => 'application/json', 'REMOTE_ADDR' => $this->ip];

        if ($this->origin !== null) {
            $headers['HTTP_ORIGIN'] = $this->origin;
            $headers['HTTP_REFERER'] = $this->origin.'/';
        }

        if (isset($this->cookies['XSRF-TOKEN'])) {
            $headers['HTTP_X_XSRF_TOKEN'] = $this->cookies['XSRF-TOKEN'];
        }

        $content = null;
        if ($json !== null) {
            $headers['CONTENT_TYPE'] = 'application/json';
            $content = (string) json_encode($json);
        }

        $response = $this->test->call($method, $uri, [], $this->cookies, [], [...$headers, ...$server], $content);

        foreach ($response->baseResponse->headers->getCookies() as $cookie) {
            if ($cookie->isCleared()) {
                unset($this->cookies[$cookie->getName()]);
            } else {
                $this->cookies[$cookie->getName()] = (string) $cookie->getValue();
            }
        }

        return $response;
    }

    public function sessionCookie(): ?string
    {
        return $this->cookies[config()->string('session.cookie')] ?? null;
    }

    public function forgetCsrfCookie(): void
    {
        unset($this->cookies['XSRF-TOKEN']);
    }

    /**
     * @param  array<string, string>  $cookies
     */
    public function useCookies(array $cookies): void
    {
        $this->cookies = $cookies;
    }

    /**
     * @return array<string, string>
     */
    public function cookies(): array
    {
        return $this->cookies;
    }
}
