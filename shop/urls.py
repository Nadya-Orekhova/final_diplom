from django.urls import path

from shops.views import (CategoryView, PartnerState, PartnerUpdate,
                         ProductInfoView, ShopView)

app_name = 'shops'

urlpatterns = [
    path('categories/', CategoryView.as_view(), name='categories'),
    path('shops/', ShopView.as_view(), name='shops'),
    path('partner/update/', PartnerUpdate.as_view(), name='partner-update'),
    path('partner/state/', PartnerState.as_view(), name='partner-state'),
    path('products/', ProductInfoView.as_view(), name='shops'),
]


