<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use App\Models\User;

class AuthController extends Controller
{
    //Signup
    public function signup(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'fullname' => 'required|string|max:255',
            'username' => 'required|string|min:2',
            'password' => 'required|string|min:5'
        ]);

        if ($validator->fails()) {
            # code...
            return response()->json($validator->errors());
        }

        //create new user
        $user = User::create([
            'fullname' => $request->fullname,
            'username' => $request->username,
            'password' => Hash::make($request->password)
        ]);
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'data' => $user,
            'access_token' => $token,
            'token_type' => 'Bearer'
        ]);
    }

    public function login(Request $request)
    {
        # code...
        if (! Auth::attempt($request->only('username','password'))) {
            # code...
            return response()->json([
                'message' => 'Not Authorized'
            ], 401);
        }
        $user = User::where('username', $request->username)->firstOrFail();

        $token = $user->createToken('auth_token')->plainTextToken;
        return response()->json([
            'message' => 'Login success',
            'access_token' => $token,
            'token_type' => 'Bearer'
        ]);
    }

    public function logout()
    {
        Auth::user()->tokens()->delete();
        return response()->json([
            'message' => 'logout success'
        ]);
    }
}
