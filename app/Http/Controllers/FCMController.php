<?php

namespace App\Http\Controllers;

use App\Models\DeviceToken;
use Illuminate\Http\Request;

class FCMController extends Controller
{
    public function register(Request $request)
    {
        $request->validate(['fcm_token' => 'required|string']);

        DeviceToken::updateOrCreate(
            ['fcm_token' => $request->fcm_token],
            ['last_seen_at' => now()]
        );

        return response()->json(['message' => 'Token terdaftar']);
    }
}
