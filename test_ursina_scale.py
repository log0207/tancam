from ursina import *
app = Ursina(borderless=False)
mesh = load_model('cube')
e = Entity(model=mesh)
print("BOUNDS_TYPE:", type(e.bounds))
print("BOUNDS_VALUE:", e.bounds)
if hasattr(e.bounds, 'size'):
    print("SIZE_PROP:", e.bounds.size)
elif isinstance(e.bounds, tuple):
    print("SIZE_TUPLE:", e.bounds[1])
sys.exit(0)
