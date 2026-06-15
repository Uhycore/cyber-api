<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class DeviceToken extends Model
{
    protected $fillable = ['fcm_token', 'device_info', 'last_seen_at'];
}
