from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase


class BenchmarkRequirementTest(APITestCase):
    """Test the Benchmark_Requirement APIv2 endpoint."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.benchmark_type = self.create_test_type()
        self.benchmark_category = self.create_category(self.benchmark_type)

        r = self.create(
            category = self.benchmark_category,
            objective_number = "1.0",
            objective = "OWASP ASVS Objective",
            references = "http://localhost"
        )
        self.assertEqual(r.status_code, 201)

    def create_category(self, type):
        r = self.client.post(reverse("benchmark_category-list"),  {
            'type': type,
            'name': 'OWASP ASVS 1.1 Category 2',
            'objective': 'OWASP ASVS 1.1 Category 2 Objective'
        }, format='json')
        return r.json()["id"]

    def create(self, **kwargs):
        return self.client.post(reverse("benchmark_requirement-list"), kwargs, format="json")

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

    def test_benchmark_requirement_list(self):
        r = self.client.get(reverse("benchmark_requirement-list"))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        benchmark_requirement_list = r.json()["results"]
        self.assertGreaterEqual(len(benchmark_requirement_list), 1, r.content[:1000])
        self.assertEqual(1, benchmark_requirement_list[0]['category'])
        self.assertEqual('OWASP ASVS Objective', benchmark_requirement_list[0]['objective'])
        self.assertEqual('http://localhost', benchmark_requirement_list[0]['references'])
        self.assertTrue(benchmark_requirement_list[0]['enabled'])

    def test_benchmark_requirement_add(self):
        r = self.client.post(reverse("benchmark_requirement-list"),  {
            'category': 1,
            'objective_number': '1.2',
            'objective': 'OWASP ASVS Requirement Objective'
        }, format='json')
        self.assertEqual(r.status_code, 201, r.content[:1000])

    def test_benchmark_requirement_delete(self):
        r = self.create(
            category = self.benchmark_category,
            objective_number = "0.0",
            objective = "Objective to be deleted",
            references = "http://localhost"
        )

        delete_id =  r.json()["id"]

        r = self.client.delete(reverse("benchmark_requirement-detail", args=(delete_id,)))
        self.assertEqual(r.status_code, 204)

        r = self.client.get(reverse("benchmark_requirement-detail", args=(delete_id,)))
        self.assertEqual(r.status_code, 404)

    def test_normal_user_can_list_benchmark_requirement(self):
        token = self.get_normal_test_user_token()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token)

        r = self.client.get(reverse("benchmark_requirement-list"))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        benchmark_requirement_list = r.json()["results"]
        self.assertGreaterEqual(len(benchmark_requirement_list), 1, r.content[:1000])
        self.assertEqual(1, benchmark_requirement_list[0]['category'])
        self.assertEqual('OWASP ASVS Objective', benchmark_requirement_list[0]['objective'])
        self.assertEqual('http://localhost', benchmark_requirement_list[0]['references'])
        self.assertTrue(benchmark_requirement_list[0]['enabled'])

    def test_normal_user_cannot_add_benchmark_requirement(self):
        token = self.get_normal_test_user_token()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token)

        r = self.client.post(reverse("benchmark_requirement-list"),  {
            'category': 1,
            'objective_number': '1.2',
            'objective': 'OWASP ASVS Requirement Objective'
        }, format='json')

        self.assertEqual(r.status_code, 403, r.content[:1000])

    def test_normal_user_cannot_delete_benchmark_requirement(self):
        token = Token.objects.get(user__username="admin")
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        r = self.create(
            category = self.benchmark_category,
            objective_number = "0.0",
            objective = "Objective to be deleted",
            references = "http://localhost"
        )

        delete_id =  r.json()["id"]

        token = self.get_normal_test_user_token()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token)

        r = self.client.delete(reverse("benchmark_requirement-detail", args=(delete_id,)))
        self.assertEqual(r.status_code, 403, r.content[:1000])