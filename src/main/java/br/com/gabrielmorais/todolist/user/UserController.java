package br.com.gabrielmorais.todolist.user;

import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;


/* Modificadores
 * public
 * private
 * protected
 */

 @RestController
 @RequestMapping("/users")

public class UserController {

    @PostMapping("/")
    

    public void create(@RequestBody UserModel userModel){

       System.out.println(userModel.getUsername());

    }
    
}
