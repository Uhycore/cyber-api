<?php

namespace App\Http\Controllers;

use App\Services\FCMService;
use Illuminate\Http\Request;

class CowrieWebhookController extends Controller
{
    // app/Http/Controllers/CowrieWebhookController.php
    public function handle(Request $request, FCMService $fcm)
    {
        $event = $request->input('eventid');

        // Hanya proses login sukses
        if ($event !== 'cowrie.login.success') {
            return response()->json(['ok' => true]);
        }

        $ip       = $request->input('src_ip', '-');
        $username = $request->input('username', '-');
        $password = $request->input('password', '-');

        // Langsung broadcast notif ke semua device
        $fcm->broadcastAll(
            title: '🚨 Login Sukses ke Honeypot!',
            body: "IP: {$ip} | {$username}:{$password}",
            data: [
                'type'     => 'honeypot_login_success',
                'ip'       => $ip,
                'username' => $username,
            ]
        );

        return response()->json(['ok' => true]);
    }
}
