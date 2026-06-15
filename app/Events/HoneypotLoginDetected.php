<?php
namespace App\Events;

use Illuminate\Broadcasting\Channel;
use Illuminate\Contracts\Broadcasting\ShouldBroadcast;
use Illuminate\Queue\SerializesModels;

class HoneypotLoginDetected implements ShouldBroadcast
{
    use SerializesModels;

    public function __construct(
        public string $srcIp,
        public string $username,
        public string $password,
        public string $timestamp,
    ) {}

    public function broadcastOn(): Channel
    {
        return new Channel('honeypot');
    }

    public function broadcastAs(): string
    {
        return 'login.success';
    }
}
