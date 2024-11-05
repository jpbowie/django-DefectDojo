from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase


class BenchmarkTypeTest(APITestCase):
    """Test the Benchmark_Type APIv2 endpoint."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        r = self.create(
            name = 'OWASP ASVS',
            version = '1.1',
            benchmark_source = 'OWASP ASVS'
        )
        self.assertEqual(r.status_code, 201)

    def create(self, **kwargs):
        return self.client.post(reverse("benchmark_type-list"), kwargs, format="json")

    def get_normal_test_user_token(self):
        self.client.post(reverse("user-list"), {
            "username": "test_user",
            "email": "test@example.com",
            "password": 'Password-Simple-And-1Weak',
        }, format="json")
        r = self.client.post(reverse("api-token-auth"), {
            "username": "test_user",
            "password": 'Password-Simple-And-1Weak',
        }, format="json")
        token = r.json()['token']
        return token

    def test_benchmark_type_list(self):
        r = self.client.get(reverse("benchmark_type-list"))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        benchmark_type_list = r.json()["results"]
        self.assertGreaterEqual(len(benchmark_type_list), 1, r.content[:1000])
        self.assertEqual('OWASP ASVS', benchmark_type_list[0]['name'])
        self.assertEqual('1.1', benchmark_type_list[0]['version'])
        self.assertEqual('OWASP ASVS', benchmark_type_list[0]['benchmark_source'])
        self.assertTrue(benchmark_type_list[0]['enabled'])

    def test_benchmark_type_add(self):
        r = self.client.post(reverse("benchmark_type-list"),  {
            'name': 'OWASP ASVS',
            'version': '2.0',
            'benchmark_source': 'OWASP ASVS'
            }, format='json')
        self.assertEqual(r.status_code, 201, r.content[:1000])

    def test_benchmark_type_delete(self):
        r = self.create(name = 'To Be Deleted', version = '1.0', benchmark_source = 'OWASP ASVS')
        delete_id =  r.json()["id"]

        r = self.client.delete(reverse("benchmark_type-detail", args=(delete_id,)))
        self.assertEqual(r.status_code, 204)

        r = self.client.get(reverse("benchmark_type-detail", args=(delete_id,)))
        self.assertEqual(r.status_code, 404)

    def test_normal_user_can_list_benchmark_type(self):
        token = self.get_normal_test_user_token()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token)

        r = self.client.get(reverse("benchmark_type-list"))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        benchmark_type_list = r.json()["results"]
        self.assertGreaterEqual(len(benchmark_type_list), 1, r.content[:1000])
        self.assertEqual('OWASP ASVS', benchmark_type_list[0]['name'])
        self.assertEqual('1.1', benchmark_type_list[0]['version'])
        self.assertEqual('OWASP ASVS', benchmark_type_list[0]['benchmark_source'])
        self.assertTrue(benchmark_type_list[0]['enabled'])

    def test_normal_user_cannot_add_benchmark_type(self):
        token = self.get_normal_test_user_token()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token)

        r = self.client.post(reverse("benchmark_type-list"),  {
            'name': 'OWASP ASVS',
            'version': '2.1',
            'benchmark_source': 'OWASP ASVS'
        }, format='json')
        self.assertEqual(r.status_code, 403, r.content[:1000])

    def test_normal_user_cannot_delete_benchmark_type(self):
        token = Token.objects.get(user__username="admin")
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        r = self.create(name = 'To Be Deleted', version = '1.0', benchmark_source = 'OWASP ASVS')
        delete_id =  r.json()["id"]

        token = self.get_normal_test_user_token()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token)

        r = self.client.delete(reverse("benchmark_type-detail", args=(delete_id,)))
        self.assertEqual(r.status_code, 403)
