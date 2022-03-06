<?php

namespace Controllers;

use Classes\Email;
use Model\Usuario;
use MVC\Router;

class LoginController {
    public static function login(Router $router) {
        session_start();
        YaAuth();
        $alertas = [];
        if($_SERVER['REQUEST_METHOD'] === 'POST'){

            $usuario = new Usuario($_POST);

            $alertas = $usuario->validarLogin();

            if(empty($alertas)) {
                // Verificar que el usuario exista
                $usuario = Usuario::where('email', $usuario->email);

                if(!$usuario || !$usuario->confirmado){
                    Usuario::setAlerta('error', 'El Usuario no existe o no está confirmado');
                }else {
                    // El usuario existe
                    if(password_verify($_POST['password'], $usuario->password)){
                        // Iniciar la sesión
                        session_start();
                        $_SESSION['id'] = $usuario->id;
                        $_SESSION['nombre'] = $usuario->nombre;
                        $_SESSION['email'] = $usuario->email;
                        $_SESSION['login'] = true;

                        // Redireccionar
                        header('Location: /dashboard');
                    }else {
                        Usuario::setAlerta('error', 'Password Incorrecto');
                    }
                }
                
            }
            
        }

        $alertas = Usuario::getAlertas();
        $router->render('/auth/login',[
            'titulo' => 'Iniciar Sesión',
            'alertas' => $alertas
        ]);
    }

    public static function logout() {
        session_start();
        $_SESSION = [];

        header('Location: /');

        
    }

    public static function crear(Router $router) {
        session_start();
        YaAuth();
        $alertas = [];
        $usuario  = new Usuario;

        if($_SERVER['REQUEST_METHOD'] === 'POST'){
            $usuario->sincronizar($_POST);
            $alertas = $usuario->validarNuevaCuenta();
            
            if(empty($alertas)) {
                $existeUsuario  = Usuario::where('email', $usuario->email);

                if($existeUsuario) {
                    Usuario::setAlerta('error', 'El Usuario ya está registrado');
                    $alertas = Usuario::getAlertas();
                }else {
                    // Hashear el password
                    $usuario->hashPassword();
                    
                    // Eliminar password2 -> elimina el campo del objeto de $usuario(unset)
                    unset($usuario->password2);

                    // Generar el token
                    $usuario->generarToken();

                    // Crear un nuevo usuario
                    $resultado = $usuario->guardar();

                    // Enviar email
                    $email = new Email($usuario->email, $usuario->nombre, $usuario->token);
                    $email->enviarConfirmacion();

                    if($resultado) {
                        header('Location: /mensaje');
                    }
                     
                }
            }
        }

        $router->render('/auth/crear',[
            'titulo' => 'Crear Cuenta',
            'usuario' => $usuario,
            'alertas' => $alertas
        ]);
    }

    public static function olvide(Router $router) {
        session_start();
        YaAuth();

        $alertas = [];
        if($_SERVER['REQUEST_METHOD'] === 'POST'){
            
            $usuario = new Usuario($_POST);
            $alertas = $usuario->validarEmail();

            if(empty($alertas)) {
                // Buscar el usuario
                $usuario = Usuario::where('email', $usuario->email);

                if($usuario && $usuario->confirmado) {
                    
                    // Generar un nuevo token
                    $usuario->generarToken();
                    unset($usuario->password2);
                    // Actualizar el usuario
                    $usuario->guardar();

                    //Enviar el email
                    $email = new Email($usuario->email,$usuario->nombre,$usuario->token);
                    $email->enviarInstrucciones();

                    // Imprimir la alerta
                    Usuario::setAlerta('exito', 'Hemos enviado las instrucciones a tu email');

                    
                }else {
                    Usuario::setAlerta('error', 'El usuario no existe o no está confirmado');
                    
                }
                
            }
        }

        $alertas = Usuario::getAlertas();
        $router->render('auth/olvide', [
            'titulo' => 'Olvide mi Password',
            'alertas' => $alertas
        ]);
    }


    public static function reestablecer(Router $router) {
    session_start();
    YaAuth();
        $alertas = [];
        $token = s($_GET['token']);
        $mostrar = true;

        if(!$token) header('Location: /');

        // Identificar el usuario con este token
        $usuario = Usuario::where('token', $token);
        
        if(empty($usuario)) {
            Usuario::setAlerta('error', 'Token no válido');
            $mostrar = false;
        }
        
        if($_SERVER['REQUEST_METHOD'] === 'POST'){
            
            // Añadir el nuevo password
            $usuario->sincronizar($_POST);

            // Validar el password
            $alertas = $usuario->validarPassword();

            if(empty($alertas)) {
                // Hashear el nuevo password
                $usuario->hashPassword();
                

                // Eliminar el Token
                $usuario->token = '';

                
                // Guardar el usuario en la BD
                $resultado = $usuario->guardar();

                // Redireccionar
                header('Location: /');
                
            }
            
        }
        $alertas = Usuario::getAlertas();
        $router->render('auth/reestablecer',[
            'titulo' => 'Reestablecer Password',
            'alertas' => $alertas,
            'mostrar' => $mostrar
        ]);
    }

    public static function mensaje(Router $router) {
        session_start();
        YaAuth();
        $router->render('auth/mensaje',[
            'titulo' => 'Cuenta Creada Exitosamente'
        ]);

    }

    
    public static function confirmar(Router $router) {
        session_start();
        YaAuth();
        $alertas = [];

        $token = s($_GET['token']);

        if(!$token) header('Location: /');

            // Econtrar al usuario
            $usuario = Usuario::where('token', $token);

            if(empty($usuario)) {
                // No se encontró el usuario con ese token
                Usuario::setAlerta('error', 'Token no válido');
            }else {
                // Confirmar la cuenta
                $usuario->confirmado = 1;
                $usuario->token = '';
                unset($usuario->password2);

                // Guardar en la BD
                $usuario->guardar();

                Usuario::setAlerta('exito', 'Cuenta Comprobada Satisfactoriamente');
            }

            $alertas = Usuario::getAlertas();
        

        $router->render('auth/confirmar',[
            'titulo' => 'Cuenta Confirmada Exitosamente',
            'alertas' => $alertas
        ]);

    }
}