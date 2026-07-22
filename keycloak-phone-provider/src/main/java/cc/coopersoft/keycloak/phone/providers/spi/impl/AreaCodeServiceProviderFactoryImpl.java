package cc.coopersoft.keycloak.phone.providers.spi.impl;

import cc.coopersoft.keycloak.phone.providers.spi.AreaCodeService;
import cc.coopersoft.keycloak.phone.providers.spi.AreaCodeServiceProviderFactory;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class AreaCodeServiceProviderFactoryImpl implements AreaCodeServiceProviderFactory {

    @Override
    public AreaCodeService create(KeycloakSession session) {
        // 不能把 AreaCodeService 实例缓存为工厂字段：它持有本次请求的 KeycloakSession，
        // 请求结束该 session 即被关闭，跨请求复用会导致线程不安全及"悬空 session"问题。
        // 区号列表本身已经在 AreaCodeService 内部通过 static volatile 缓存，
        // 每次请求 new 一个轻量实例开销可忽略。
        return new AreaCodeService(session);
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "areacode";
    }
}
