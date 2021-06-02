package com.example.demo.service;

public interface UserDetails {

    public boolean isAccountNonExpired();

    public boolean isAccountNonLocked();

    public boolean isCredentialsNonExpired();

    public boolean isEnable();
}
