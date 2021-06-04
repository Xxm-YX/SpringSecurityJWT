package com.example.demo.web.filter;

import com.example.demo.service.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Date;

/**
 * 一个是用户登录的过滤器，在用户的登录的过滤器中校验用户是否登录成功，如果登录成功，则生成一个token返回给客户端，登录失败则给前端一个登录失败的提示。
 * 第二个过滤器则是当其他请求发送来，校验token的过滤器，如果校验成功，就让请求继续执行。
 */
public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter  {


    protected JwtLoginFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    protected JwtLoginFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    public JwtLoginFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher(defaultFilterProcessesUrl));
        setAuthenticationManager(authenticationManager);

    }

    protected JwtLoginFilter(RequestMatcher requiresAuthenticationRequestMatcher, AuthenticationManager authenticationManager) {
        super(requiresAuthenticationRequestMatcher, authenticationManager);
    }

    /**
     * attemptAuthentication方法中，我们从登录参数中提取出用户名密码，然后调用AuthenticationManager.authenticate()方法去进行自动校验。
     *
     *
     * authenticate 验证
     * 做校验的方法
     * @param req
     * @param res
     * @return
     * @throws AuthenticationException
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException, IOException, ServletException {
        User user = new ObjectMapper().readValue(req.getInputStream(),User.class);
        return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()));//这个方法进行账号和用户名的验证
    }

    /**
     * 第二步如果校验成功，就会来到successfulAuthentication回调中，
     * 在successfulAuthentication方法中，将用户角色遍历然后用一个 ,
     * 连接起来，然后再利用Jwts去生成token，按照代码的顺序，
     * 生成过程一共配置了四个参数，
     * 分别是用户角色、主题、过期时间以及加密算法和密钥，
     * 然后将生成的token写出到客户端。
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        StringBuffer as = new StringBuffer();
        for (GrantedAuthority authority : authorities) {
            as.append(authority.getAuthority())
                    .append(",");
        }
        String jwt = Jwts.builder()
                .claim("authorities",as)//配置用户角色
                .setSubject(authResult.getName())//主题
                .setExpiration(new Date(System.currentTimeMillis() + 10 * 60 * 1000)) //过期时间
                .signWith(SignatureAlgorithm.HS256,"zyx@123")//密钥
                .compact();
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        out.write(new ObjectMapper().writeValueAsString(jwt));
        out.flush();
        out.close();
    }

    /**
     * 第二步如果校验失败就会来到unsuccessfulAuthentication方法中，在这个方法中返回一个错误提示给客户端即可。
     * @param request
     * @param response
     * @param failed
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();//打印流
        out.write("登录失败");
        out.flush();
        out.close();
    }
}
