// Fixture para análise estática; não compõe uma aplicação executável.
class OrdersService {
    async Task LoadOrders() {
        foreach (var id in customerIds) {
            var orders = db.Orders.Where(order => order.CustomerId == id).ToList();
        }
        var filtered = (await db.Orders.ToListAsync()).Where(order => order.Active).ToList();
    }
}
