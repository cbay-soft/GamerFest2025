<?php

namespace App\Actions\Fortify;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Laravel\Fortify\Contracts\CreatesNewUsers;
use Laravel\Jetstream\Jetstream;
use PragmaRX\Google2FA\Google2FA;

class CreateNewUser implements CreatesNewUsers
{
    use PasswordValidationRules;

    /**
     * Validate and create a newly registered user.
     *
     * @param  array<string, string>  $input
     */
    public function create(array $input): User
    {
        // Validar los datos del formulario
        Validator::make($input, [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => $this->passwordRules(),
            'terms' => Jetstream::hasTermsAndPrivacyPolicyFeature() ? ['accepted', 'required'] : '',
        ])->validate();

        // Crear el usuario
        $user = User::create([
            'name' => $input['name'],
            'email' => $input['email'],
            'password' => Hash::make($input['password']),
        ]);

        // Habilitar 2FA automáticamente para usuarios no administradores
        if (!$this->isAdmin($user)) {
            $google2fa = new Google2FA();

            $user->forceFill([
                'two_factor_secret' => encrypt($google2fa->generateSecretKey()), // Generar un secreto válido
                'two_factor_recovery_codes' => encrypt(json_encode($this->generateRecoveryCodes())),
            ])->save();
        }

        return $user;
    }

    /**
     * Verificar si el usuario es administrador.
     *
     * @param  \App\Models\User  $user
     * @return bool
     */
    protected function isAdmin(User $user): bool
    {
        // Aquí puedes verificar si el usuario es administrador (ejemplo: un campo `is_admin` en la tabla de usuarios)
        return $user->is_admin ?? false;
    }

    /**
     * Generar códigos de recuperación.
     *
     * @return array
     */
    protected function generateRecoveryCodes(): array
    {
        $codes = [];

        for ($i = 0; $i < 8; $i++) {
            $codes[] = bin2hex(random_bytes(5));
        }

        return $codes;
    }
}
