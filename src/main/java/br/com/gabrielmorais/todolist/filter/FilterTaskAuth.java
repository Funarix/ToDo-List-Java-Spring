package br.com.gabrielmorais.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.gabrielmorais.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@Component
public class FilterTaskAuth extends OncePerRequestFilter{

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

                var servletPath = request.getServletPath();

                System.out.println("PATH" + servletPath);

                if(servletPath.startsWith("/tasks/")){


                    // Pegar o usuário e senha

                var authorization = request.getHeader("Authorization");
              

                var authEncoded = authorization.substring("Basic".length()).trim();

                byte[]authDecode =  Base64.getDecoder().decode(authEncoded);

                var authString =  new String(authDecode);

                String[] credenditials =  authString.split(":");
                String username = credenditials[0];
                String password = credenditials[1];



                // Validar usuário

                var user = this.userRepository.findByUsername(username);
                
                if(user == null){

                    response.sendError(401);

                } else{

                      // Validar a senha

                      var passwordVerify =  BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                      
                      if(passwordVerify.verified){

                        request.setAttribute("idUser", user.getId());

                        filterChain.doFilter(request, response);


                      }else{

                        response.sendError(401);


                      }



                      

                }


                }else{

                    filterChain.doFilter(request, response);


                }

                     
                
    }

    
    
    
}
