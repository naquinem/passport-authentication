<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Requests\LoginRequest;
use App\Http\Resources\UserResource;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Http\Requests\RegisterRequest;

class AuthController extends Controller
{
    public function register(RegisterRequest $request)
            {
                $data = $request->validated();
                $user = User::create([
                    'username' => $data['username'],
                    'email' => $data['email'],
                    'password' => Hash::make($data['password']),
                ]);
                $token = $user->createToken('token')->accessToken;
                return response([
                    'status' => 200,
                    'message' => 'Successfully registered crendentials',
                ]);
            }
            public function login(LoginRequest $request)
            {
                $data = $request->validated();
                $user = User::where('email', $data['email'])->first();

                if(!$user || !Hash::check($data['password'], $user->password)){
                    return response([
                        'status' => 422,
                        'message' => 'Email or password is not correct'
                    ], 422);
                }
                $token = $user->createToken('token')->accessToken;
                return response([
                    'status' => 200,
                    'token' => $token
                ]);
            }
            public function user()
            {
                $user = Auth::user();

                return response()->json([
                    'user' => new UserResource($user),
                ]);
            }
            public function logout()
            {
                auth()->user()->token()->revoke();
                return response()->json([
                    'message' => 'Successfully logout'
                ]);

            }
}
