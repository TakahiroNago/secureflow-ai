<?php

namespace App\Ai\Evaluation;

use InvalidArgumentException;
use JsonException;

/**
 * The evaluation set (resources/security/evaluation/requests.json): a version and a list of requests, with ids
 * that do not repeat.
 */
final readonly class RequestSet
{
    /**
     * @param  list<EvaluationRequest>  $requests
     */
    public function __construct(
        public string $version,
        public array $requests,
    ) {}

    /**
     * From the text of the file. Reading it is the command's business: nothing in app/Ai touches a file.
     *
     * @throws InvalidArgumentException when the text is not an evaluation set
     */
    public static function fromJson(string $raw): self
    {
        try {
            $decoded = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('The evaluation set is not valid JSON: '.$exception->getMessage());
        }

        if (! is_array($decoded) || ! is_string($decoded['version'] ?? null) || ! is_array($decoded['requests'] ?? null)) {
            throw new InvalidArgumentException('The evaluation set needs a version and a list of requests');
        }

        $requests = [];
        $ids = [];
        foreach ($decoded['requests'] as $entry) {
            if (! is_array($entry)) {
                throw new InvalidArgumentException('Every request must be an object');
            }
            /** @var array<string, mixed> $entry */
            $request = EvaluationRequest::fromArray($entry);
            if (isset($ids[$request->id])) {
                throw new InvalidArgumentException('The id is used twice: '.$request->id);
            }
            $ids[$request->id] = true;
            $requests[] = $request;
        }

        if ($requests === []) {
            throw new InvalidArgumentException('The evaluation set has no requests');
        }

        return new self($decoded['version'], $requests);
    }

    /**
     * @param  list<string>  $ids
     */
    public function only(array $ids): self
    {
        $wanted = array_flip($ids);
        $requests = array_values(array_filter($this->requests, fn (EvaluationRequest $request) => isset($wanted[$request->id])));

        foreach ($ids as $id) {
            if (! in_array($id, array_map(fn (EvaluationRequest $request) => $request->id, $requests), true)) {
                throw new InvalidArgumentException('There is no request with the id '.$id);
            }
        }

        return new self($this->version, $requests);
    }
}
