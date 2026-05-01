<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;


Route::get('/test', function () {
    return response()->json([
        'success' => true,
        'message' => 'API jalan'
    ]);
});

// Public
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);

// Protected
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/user', [AuthController::class, 'profile']);
});
