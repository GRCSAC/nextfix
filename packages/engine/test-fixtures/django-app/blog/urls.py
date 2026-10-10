from django.urls import path

from . import views
from .views import PostView

urlpatterns = [
    path('', views.index, name='index'),
    path('post/<int:pk>/', PostView.as_view(), name='post'),
    path('render/', views.render_post, name='render'),
]
