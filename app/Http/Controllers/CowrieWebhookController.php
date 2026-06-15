<?php

namespace App\Http\Controllers;

use App\Events\HoneypotLoginDetected;
use Illuminate\Http\Request;

class CowrieWebhookController extends Controller
{
    public function handle(Request $request)
    {
        $event = $request->input('eventid');

        if ($event !== 'cowrie.login.success') {
            return response()->json(['ok' => true]);
        }

        // Broadcast via WebSocket
        broadcast(new HoneypotLoginDetected(
            srcIp: $request->input('src_ip', '-'),
            username: $request->input('username', '-'),
            password: $request->input('password', '-'),
            timestamp: $request->input('timestamp', now()->toISOString()),
        ));

        return response()->json(['ok' => true]);
    }
}
