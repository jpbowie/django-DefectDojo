from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase


class BenchmarkCategoryTest(APITestCase):
    """Test the Benchmark_Category APIv2 endpoint."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.benchmark_type = self.create_test_type()

        r = self.create(
            type = self.benchmark_type,
            name = "OWASP ASVS V1.1",
            objective = "OWASP ASVS Objective",
            references = "http://localhost"
        )
        self.assertEqual(r.status_code, 201)

    def create(self, **kwargs):
        return self.client.post(reverse("benchmark_category-list"), kwargs, format="json")

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

    def create_test_type(self):
        r = self.client.post(reverse("benchmark_type-list"), {
            "name": "OWASP ASVS",
            "version": "1.1",
            "benchmark_source": "OWASP ASVS"
        }, format="json"
                             )
        return r.json()["id"]

    def test_benchmark_category_list(self):
        r = self.client.get(reverse("benchmark_category-list"))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        benchmark_category_list = r.json()["results"]
        self.assertGreaterEqual(len(benchmark_category_list), 1, r.content[:1000])
        self.assertEqual('OWASP ASVS V1.1', benchmark_category_list[0]['name'])
        self.assertEqual('OWASP ASVS Objective', benchmark_category_list[0]['objective'])
        self.assertEqual('http://localhost', benchmark_category_list[0]['references'])
        self.assertTrue(benchmark_category_list[0]['enabled'])

    def test_benchmark_category_add(self):
        r = self.client.post(reverse("benchmark_category-list"),  {
            'type': 1,
            'name': 'OWASP ASVS 1.1 Category 2',
            'objective': 'OWASP ASVS 1.1 Category 2 Objective'
        }, format='json')
        self.assertEqual(r.status_code, 201, r.content[:1000])

    def test_benchmark_category_delete(self):
        r = self.create(
            type = self.benchmark_type,
            name = "To Be Deleted",
            objective = "Objective to be deleted",
            references = "http://localhost"
        )
        delete_id =  r.json()["id"]

        r = self.client.delete(reverse("benchmark_category-detail", args=(delete_id,)))
        self.assertEqual(r.status_code, 204)

        r = self.client.get(reverse("benchmark_category-detail", args=(delete_id,)))
        self.assertEqual(r.status_code, 404)

    def test_normal_user_can_list_benchmark_category(self):
        token = self.get_normal_test_user_token()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token)

        r = self.client.get(reverse("benchmark_category-list"))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        benchmark_category_list = r.json()["results"]
        self.assertGreaterEqual(len(benchmark_category_list), 1, r.content[:1000])
        self.assertEqual('OWASP ASVS V1.1', benchmark_category_list[0]['name'])
        self.assertEqual('OWASP ASVS Objective', benchmark_category_list[0]['objective'])
        self.assertEqual('http://localhost', benchmark_category_list[0]['references'])
        self.assertTrue(benchmark_category_list[0]['enabled'])

    def test_normal_user_cannot_add_benchmark_category(self):
        token = self.get_normal_test_user_token()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token)

        r = self.client.post(reverse("benchmark_category-list"),  {
            'type': 1,
            'name': 'OWASP ASVS 1.1 Category 2',
            'objective': 'OWASP ASVS 1.1 Category 2 Objective'
        }, format='json')
        self.assertEqual(r.status_code, 403, r.content[:1000])

    def test_normal_user_cannot_delete_benchmark_type(self):
        token = Token.objects.get(user__username="admin")
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        r = self.create(
            type = self.benchmark_type,
            name = "To Be Deleted",
            objective = "Objective to be deleted",
            references = "http://localhost"
        )
        delete_id =  r.json()["id"]

        token = self.get_normal_test_user_token()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token)

        r = self.client.delete(reverse("benchmark_category-detail", args=(delete_id,)))
        self.assertEqual(r.status_code, 403, r.content[:1000])
