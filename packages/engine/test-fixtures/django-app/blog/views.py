import markdown
import yaml
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse
from django.views import View


def index(request):
    return HttpResponse('ok')


@login_required
def render_post(request):
    body = request.POST['body']
    return HttpResponse(markdown.markdown(body))


class PostView(LoginRequiredMixin, View):
    def get(self, request, pk):
        return HttpResponse(str(pk))

    def post(self, request, pk):
        data = yaml.load(request.body)
        return HttpResponse(str(data))
