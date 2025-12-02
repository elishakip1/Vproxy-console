@app.route('/admin/pool', methods=['GET', 'POST'])
@admin_required
def admin_pool():
    settings = get_app_settings()
    if request.method == 'POST':
        # ... existing code ...
    
    count = get_pool_count()
    provider_counts = get_pool_count_by_provider()
    counts = {
        "total": count,
        "pyproxy": provider_counts.get("pyproxy", 0),
        "piaproxy": provider_counts.get("piaproxy", 0)
    }
    
    return render_template('admin_pool.html', count=count, settings=settings, counts=counts)
