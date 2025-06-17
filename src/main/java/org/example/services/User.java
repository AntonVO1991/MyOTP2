package org.example.services;

import org.example.data.UserDao;

import java.util.List;

public class User {

    private final UserDao userDao;

    public User(UserDao userDao) {
        this.userDao = userDao;
    }

    public List<org.example.model.User> getAllUsers() {
        return userDao.findAllUsers();
    }

    public boolean isExistAdmin() {
        List<org.example.model.User> admins = userDao.findAllAdmins();
        return !admins.isEmpty(); // Вернём true, если хотя бы один администратор есть
    }

    public org.example.model.User getUserByUsername(String username) {
        return userDao.findUserByUsername(username);
    }

    public boolean addUser(org.example.model.User user) {
        return userDao.saveUser(user);
    }

    public boolean updateUser(org.example.model.User user) {
        return userDao.updateUser(user);
    }

    public boolean deleteUser(long id) {
        return userDao.deleteUser(id);
    }

    // Новый метод для получения роли пользователя
    public String getRole(String username) {
        return userDao.getRole(username);
    }
}