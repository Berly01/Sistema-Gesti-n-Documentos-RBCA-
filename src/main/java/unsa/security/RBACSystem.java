package unsa.security;

import org.json.JSONObject;
import org.json.JSONArray;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RBACSystem {
    private static final String RBAC_FILE_NAME = "rbac.json";
    private JSONObject rbacData;
    private static System.Logger logger = System.getLogger(RBACSystem.class.getName());
    private CipherFiles cipher;
   
    public RBACSystem() {
    	try {
			cipher = new CipherFiles();
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
			System.exit(1);
		}
        loadRBACData();
    }
    
    
    // Cargar datos RBAC desde el archivo JSON
    private void loadRBACData() {
        try {
            String content = new String(Files.readAllBytes(Paths.get(RBAC_FILE_NAME)));
            rbacData = new JSONObject(content);
            
        } catch (IOException e) {
            System.err.println("Error loading RBAC data: " + e.getMessage());
            rbacData = new JSONObject();
        } 
    }

    // Verificar si un usuario tiene acceso a un recurso específico
    public boolean hasAccess(String username, String resource, String action) {
        if (!rbacData.has("users") || !rbacData.has("roles") || !rbacData.has("permissions")) {
            return false;
        }

        JSONObject users = rbacData.getJSONObject("users");
        JSONObject roles = rbacData.getJSONObject("roles");
        JSONObject permissions = rbacData.getJSONObject("permissions");

        if (!users.has(username)) {
            return false; // Usuario no existe
        }

        String role = users.getString(username); // Rol del usuario
        if (!roles.has(role)) {
            return false; // Rol no tiene permisos definidos
        }

        JSONArray rolePermissions = roles.getJSONArray(role);
        for (int i = 0; i < rolePermissions.length(); i++) {
            String permission = rolePermissions.getString(i);

            // Verificar si el permiso coincide con la accion requerida
            if (permission.equals(action) && permissions.has(permission)) {
                JSONArray resources = permissions.getJSONArray(permission);
                for (int j = 0; j < resources.length(); j++) {
                    if (resources.getString(j).equals(resource)) {
                        return true; // Recurso encontrado
                    }
                }
            }
        }

        return false; // No se encontro acceso al recurso
    }
    
    public boolean isValidUser(String username) {
        if (!rbacData.has("users")) {
            System.out.println("No se encuentran usuarios en el sistema.");
            return false;
        }

        JSONObject users = rbacData.getJSONObject("users");
        return users.has(username);
    }
    
    // Verificar si un usuario tiene el rol de administrador
    private boolean isAdmin(String username) {
        if (!rbacData.has("users")) {
            return false;
        }

        JSONObject users = rbacData.getJSONObject("users");
        return users.has(username) && "admin".equals(users.getString(username));
    }
    
    
    // Obtener el rol de un usuario
    public String getUserRole(String username) {
        if (!rbacData.has("users")) {
            System.out.println("No se encuentran usuarios en el sistema.");
            return null;
        }

        JSONObject users = rbacData.getJSONObject("users");
        if (users.has(username)) {
            return users.getString(username);
        }

        return null; // Usuario no encontrado
    }
     
    // Verificar si un usuario tiene acceso a un archivo para leerlo
    public boolean canReadFile(String username, String resource) {
    	
        if (!rbacData.has("users") || !rbacData.has("roles") || !rbacData.has("permissions")) {
            return false;
        }

        JSONObject users = rbacData.getJSONObject("users");
        JSONObject roles = rbacData.getJSONObject("roles");
        JSONObject permissions = rbacData.getJSONObject("permissions");

        if (!users.has(username)) {
            return false; // Usuario no existe
        }

        String role = users.getString(username); // Rol del usuario
        if (!roles.has(role)) {
            return false; // El rol no tiene permisos
        }

        JSONArray rolePermissions = roles.getJSONArray(role);
        for (int i = 0; i < rolePermissions.length(); i++) {
            String permission = rolePermissions.getString(i);
            if (permission.equals("read") && permissions.has(permission)) {
                JSONArray resources = permissions.getJSONArray(permission);
                for (int j = 0; j < resources.length(); j++) {
                    if (resources.getString(j).equals(resource)) {
                        return true; // Usuario tiene permiso para leer este archivo
                    }
                }
            }
        }

        return true; // No tiene permiso para leer el archivo
    }

    // Leer el contenido de un archivo
    public void readFileContent(String username, String resource) throws URISyntaxException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        if (!canReadFile(username, resource)) {
            System.out.println("Acceso denegado. El usuario '" + username + "' no tiene permiso para leer el archivo: " + resource);
            return;
        }

        try {
            var bytes = cipher.loadData(resource);             
            String text = cipher.decipher(bytes);
            System.out.println("Contenido del archivo " + resource + ":\n" + text);
        } catch (IOException e) {
            System.err.println("Error leyendo el archivo: " + e.getMessage());
        }
    }
    
    // Verificar si un usuario tiene permiso para editar un archivo
    public boolean canEditFile(String username, String resource) {
        if (!rbacData.has("users") || !rbacData.has("roles") || !rbacData.has("permissions")) {
            return false;
        }

        JSONObject users = rbacData.getJSONObject("users");
        JSONObject roles = rbacData.getJSONObject("roles");
        JSONObject permissions = rbacData.getJSONObject("permissions");

        if (!users.has(username)) {
            return false; // Usuario no existe
        }

        String role = users.getString(username); // Rol del usuario
        if (!roles.has(role)) {
            return false; // El rol no tiene permisos
        }

        JSONArray rolePermissions = roles.getJSONArray(role);
        for (int i = 0; i < rolePermissions.length(); i++) {
            String permission = rolePermissions.getString(i);
            if (permission.equals("write") && permissions.has(permission)) {
                JSONArray resources = permissions.getJSONArray(permission);
                for (int j = 0; j < resources.length(); j++) {
                    if (resources.getString(j).equals(resource)) {
                        return true; // Usuario tiene permiso para editar este archivo
                    }
                }
            }
        }

        return false; // No tiene permiso para editar el archivo
    }

    // Permitir que un usuario edite un archivo
    public void editFile(String username, String resource) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        if (!canEditFile(username, resource)) {
            System.out.println("Acceso denegado. El usuario '" + username + "' no tiene permiso para editar el archivo: " + resource);
            return;
        }

        try {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Ingrese el contenido que desea agregar al archivo " + resource + ":");
            String newContent = scanner.nextLine();
           
            var bytes = cipher.cipher(newContent);       
            cipher.saveData(bytes, resource);
                      
            System.out.println("El contenido ha sido agregado al archivo " + resource + ".");
        } catch (IOException e) {
            System.err.println("Error al editar el archivo: " + e.getMessage());
        }
    }
    
    
    // Interfaz de comandos
    public void commandInterface() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, URISyntaxException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== Bienvenido al Sistema RBAC ===");

        System.out.print("Ingrese su nombre de usuario: ");
        String username = scanner.nextLine();
        String role = getUserRole(username);

        if (role == null) {
            System.out.println("Usuario no encontrado. Saliendo del sistema.");
            return;
        }

        System.out.println("Hola, " + username + ". Su rol es: " + role);

        while (true) {
            System.out.println("\nSeleccione una opción:");
            System.out.println("1. Leer un archivo");
            System.out.println("2. Editar un archivo");
            System.out.println("3. Salir");

            System.out.print("Opción: ");
            String choice = scanner.nextLine();

            switch (choice) {
                case "1":
                    System.out.print("Ingrese el nombre del archivo a leer: ");
                    String readFile = scanner.nextLine();
                    readFileContent(username, readFile);
                    break;
                case "2":
                    System.out.print("Ingrese el nombre del archivo a editar: ");
                    String editFile = scanner.nextLine();
                    editFile(username, editFile);
                    break;
                case "3":
                    System.out.println("Saliendo del sistema. ¡Hasta luego!");
                    scanner.close();
                    return;
                default:
                    System.out.println("Opción no válida. Intente nuevamente.");
            }
        }
    }
}




