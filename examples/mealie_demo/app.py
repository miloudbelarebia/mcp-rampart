"""
Mealie-like Recipe Manager — Demo Application

This simulates the core Mealie FastAPI structure to demonstrate
how MCPRampart turns ANY FastAPI app into an MCP server — with a
pre-flight security audit and runtime prompt-injection guardrails.

─── WITHOUT MCPRampart ───
You'd need to install a separate MCP server (mealie-mcp-server),
configure it, deploy it alongside your app, keep them in sync,
AND hope nobody exposes /admin or /auth by mistake.

─── WITH MCPRampart (3 lines) ───
    rampart = MCPRampart(app)
    rampart.audit()                         # pre-flight
    rampart.enable_guardrails(policy='block')   # runtime
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

# ═══════════════════════════════════════════════════════════════════
# 1. MODELS (same as Mealie's Pydantic schemas)
# ═══════════════════════════════════════════════════════════════════


class Ingredient(BaseModel):
    note: str = ""
    food: str = ""
    quantity: float = 0
    unit: str = ""


class RecipeStep(BaseModel):
    title: str = ""
    text: str = ""


class RecipeCreate(BaseModel):
    name: str = Field(..., description="Recipe name")
    description: str = Field("", description="Short description")
    ingredients: list[Ingredient] = Field(default_factory=list)
    instructions: list[RecipeStep] = Field(default_factory=list)
    total_time: str = Field("", description="Total cooking time, e.g. '45 minutes'")
    prep_time: str = Field("", description="Preparation time")
    servings: int = Field(4, description="Number of servings")
    tags: list[str] = Field(default_factory=list)
    category: str = Field("", description="Recipe category like 'dinner', 'dessert'")


class Recipe(RecipeCreate):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    slug: str = ""
    created_at: datetime = Field(default_factory=datetime.now)


class MealPlanEntry(BaseModel):
    date: str = Field(..., description="Date in YYYY-MM-DD format")
    recipe_id: str = Field(..., description="Recipe ID to plan")
    meal_type: str = Field("dinner", description="'breakfast', 'lunch', 'dinner', or 'snack'")


class ShoppingListItem(BaseModel):
    food: str = Field(..., description="Food item name")
    quantity: float = Field(1.0)
    unit: str = Field("")
    checked: bool = Field(False)


class ShoppingList(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field("My Shopping List")
    items: list[ShoppingListItem] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════
# 2. IN-MEMORY DATABASE (simulating Mealie's SQLite/Postgres)
# ═══════════════════════════════════════════════════════════════════

DB_RECIPES: dict[str, Recipe] = {}
DB_MEAL_PLANS: list[MealPlanEntry] = []
DB_SHOPPING_LISTS: dict[str, ShoppingList] = {}

# Seed some demo data
_demo_recipes = [
    Recipe(
        id="r1",
        name="Spaghetti Carbonara",
        slug="spaghetti-carbonara",
        description="Classic Italian pasta with eggs, cheese, and pancetta",
        ingredients=[
            Ingredient(food="spaghetti", quantity=400, unit="g"),
            Ingredient(food="pancetta", quantity=200, unit="g"),
            Ingredient(food="eggs", quantity=4, unit="whole"),
            Ingredient(food="parmesan", quantity=100, unit="g"),
        ],
        instructions=[
            RecipeStep(title="Boil pasta", text="Cook spaghetti in salted water until al dente"),
            RecipeStep(title="Cook pancetta", text="Fry pancetta until crispy"),
            RecipeStep(title="Mix sauce", text="Whisk eggs with parmesan"),
            RecipeStep(title="Combine", text="Toss hot pasta with pancetta and sauce"),
        ],
        total_time="25 minutes",
        prep_time="10 minutes",
        servings=4,
        tags=["italian", "pasta", "quick"],
        category="dinner",
    ),
    Recipe(
        id="r2",
        name="Chicken Tikka Masala",
        slug="chicken-tikka-masala",
        description="Creamy and spicy Indian-style chicken curry",
        ingredients=[
            Ingredient(food="chicken breast", quantity=600, unit="g"),
            Ingredient(food="yogurt", quantity=200, unit="ml"),
            Ingredient(food="tomato sauce", quantity=400, unit="ml"),
            Ingredient(food="garam masala", quantity=2, unit="tbsp"),
            Ingredient(food="cream", quantity=100, unit="ml"),
        ],
        instructions=[
            RecipeStep(title="Marinate chicken", text="Coat chicken in yogurt and spices for 2 hours"),
            RecipeStep(title="Grill chicken", text="Grill marinated chicken until charred"),
            RecipeStep(title="Make sauce", text="Simmer tomato sauce with spices and cream"),
            RecipeStep(title="Combine", text="Add grilled chicken to the sauce and simmer 10 min"),
        ],
        total_time="2 hours 30 minutes",
        prep_time="2 hours",
        servings=4,
        tags=["indian", "curry", "spicy"],
        category="dinner",
    ),
    Recipe(
        id="r3",
        name="Avocado Toast",
        slug="avocado-toast",
        description="Simple and healthy breakfast with smashed avocado",
        ingredients=[
            Ingredient(food="sourdough bread", quantity=2, unit="slices"),
            Ingredient(food="avocado", quantity=1, unit="whole"),
            Ingredient(food="lemon juice", quantity=1, unit="tbsp"),
            Ingredient(food="chili flakes", quantity=1, unit="pinch"),
        ],
        instructions=[
            RecipeStep(title="Toast bread", text="Toast sourdough until golden"),
            RecipeStep(title="Mash avocado", text="Mash avocado with lemon and salt"),
            RecipeStep(title="Assemble", text="Spread avocado on toast, add chili flakes"),
        ],
        total_time="5 minutes",
        prep_time="3 minutes",
        servings=1,
        tags=["breakfast", "healthy", "quick"],
        category="breakfast",
    ),
]
for r in _demo_recipes:
    DB_RECIPES[r.id] = r

DB_SHOPPING_LISTS["sl1"] = ShoppingList(
    id="sl1", name="Weekly Groceries",
    items=[
        ShoppingListItem(food="Milk", quantity=2, unit="liters"),
        ShoppingListItem(food="Eggs", quantity=12, unit="pieces"),
        ShoppingListItem(food="Bread", quantity=1, unit="loaf"),
    ],
)


# ═══════════════════════════════════════════════════════════════════
# 3. FASTAPI APPLICATION (mirrors Mealie's route structure)
# ═══════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Mealie",
    description="Self-hosted recipe manager and meal planner",
    version="3.7.0",
)


# ── Recipes ──────────────────────────────────────────────────────

@app.get("/api/recipes", tags=["Recipes"])
async def get_all_recipes(
    page: int = Query(1, description="Page number"),
    per_page: int = Query(10, description="Items per page"),
    category: Optional[str] = Query(None, description="Filter by category"),
) -> dict:
    """Get all recipes with optional filtering and pagination."""
    recipes = list(DB_RECIPES.values())
    if category:
        recipes = [r for r in recipes if r.category == category]
    start = (page - 1) * per_page
    return {
        "items": [r.model_dump() for r in recipes[start:start + per_page]],
        "total": len(recipes),
        "page": page,
        "per_page": per_page,
    }


@app.get("/api/recipes/{recipe_id}", tags=["Recipes"])
async def get_recipe(recipe_id: str) -> dict:
    """Get a specific recipe by its ID."""
    recipe = DB_RECIPES.get(recipe_id)
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")
    return recipe.model_dump()


@app.post("/api/recipes", tags=["Recipes"])
async def create_recipe(data: RecipeCreate) -> dict:
    """Create a new recipe."""
    recipe = Recipe(**data.model_dump())
    recipe.slug = recipe.name.lower().replace(" ", "-")
    DB_RECIPES[recipe.id] = recipe
    return recipe.model_dump()


@app.put("/api/recipes/{recipe_id}", tags=["Recipes"])
async def update_recipe(recipe_id: str, data: RecipeCreate) -> dict:
    """Update an existing recipe."""
    if recipe_id not in DB_RECIPES:
        raise HTTPException(status_code=404, detail="Recipe not found")
    recipe = Recipe(**data.model_dump(), id=recipe_id)
    recipe.slug = recipe.name.lower().replace(" ", "-")
    DB_RECIPES[recipe_id] = recipe
    return recipe.model_dump()


@app.delete("/api/recipes/{recipe_id}", tags=["Recipes"])
async def delete_recipe(recipe_id: str) -> dict:
    """Delete a recipe by ID."""
    if recipe_id not in DB_RECIPES:
        raise HTTPException(status_code=404, detail="Recipe not found")
    del DB_RECIPES[recipe_id]
    return {"detail": "Recipe deleted"}


@app.get("/api/recipes/search", tags=["Recipes"])
async def search_recipes(
    q: str = Query(..., description="Search query for recipe name or ingredients"),
) -> dict:
    """Search recipes by name, description, or ingredients."""
    q_lower = q.lower()
    results = []
    for recipe in DB_RECIPES.values():
        if q_lower in recipe.name.lower() or q_lower in recipe.description.lower():
            results.append(recipe.model_dump())
            continue
        for ing in recipe.ingredients:
            if q_lower in ing.food.lower():
                results.append(recipe.model_dump())
                break
    return {"items": results, "total": len(results)}


# ── Meal Plans ───────────────────────────────────────────────────

@app.get("/api/households/mealplans", tags=["Meal Plans"])
async def get_meal_plans(
    start_date: Optional[str] = Query(None, description="Start date YYYY-MM-DD"),
    end_date: Optional[str] = Query(None, description="End date YYYY-MM-DD"),
) -> dict:
    """Get meal plan entries for a date range."""
    plans = DB_MEAL_PLANS
    if start_date:
        plans = [p for p in plans if p.date >= start_date]
    if end_date:
        plans = [p for p in plans if p.date <= end_date]
    return {"items": [p.model_dump() for p in plans]}


@app.post("/api/households/mealplans", tags=["Meal Plans"])
async def create_meal_plan(entry: MealPlanEntry) -> dict:
    """Add a recipe to the meal plan for a specific date."""
    if entry.recipe_id not in DB_RECIPES:
        raise HTTPException(status_code=404, detail="Recipe not found")
    DB_MEAL_PLANS.append(entry)
    return entry.model_dump()


# ── Shopping Lists ───────────────────────────────────────────────

@app.get("/api/households/shopping-lists", tags=["Shopping Lists"])
async def get_shopping_lists() -> dict:
    """Get all shopping lists."""
    return {"items": [sl.model_dump() for sl in DB_SHOPPING_LISTS.values()]}


@app.get("/api/households/shopping-lists/{list_id}", tags=["Shopping Lists"])
async def get_shopping_list(list_id: str) -> dict:
    """Get a specific shopping list by ID."""
    sl = DB_SHOPPING_LISTS.get(list_id)
    if not sl:
        raise HTTPException(status_code=404, detail="Shopping list not found")
    return sl.model_dump()


@app.post("/api/households/shopping-lists/{list_id}/items", tags=["Shopping Lists"])
async def add_shopping_list_item(list_id: str, item: ShoppingListItem) -> dict:
    """Add an item to a shopping list."""
    sl = DB_SHOPPING_LISTS.get(list_id)
    if not sl:
        raise HTTPException(status_code=404, detail="Shopping list not found")
    sl.items.append(item)
    return sl.model_dump()


# ── Tags & Categories ────────────────────────────────────────────

@app.get("/api/organizers/tags", tags=["Organizers"])
async def get_tags() -> dict:
    """Get all recipe tags."""
    tags = set()
    for recipe in DB_RECIPES.values():
        tags.update(recipe.tags)
    return {"items": sorted(tags)}


@app.get("/api/organizers/categories", tags=["Organizers"])
async def get_categories() -> dict:
    """Get all recipe categories."""
    categories = set()
    for recipe in DB_RECIPES.values():
        if recipe.category:
            categories.add(recipe.category)
    return {"items": sorted(categories)}


# ═══════════════════════════════════════════════════════════════════
# 4. MCPSENTRY INTEGRATION — BRIDGE + PRE-FLIGHT AUDIT ✨
# ═══════════════════════════════════════════════════════════════════
#
# ┌──────────────────────────────────────────────────────────────┐
# │  WITHOUT MCPRampart:                                          │
# │  → Install a separate mealie-mcp-server (500+ lines)         │
# │  → Configure API keys and endpoints                          │
# │  → Deploy a second process alongside Mealie                  │
# │  → Hope nobody exposes /admin or /auth by mistake            │
# │                                                              │
# │  WITH MCPRampart (below):                                     │
# │  → 1 line. Your app IS the MCP server.                       │
# │  → 1 more line. Pre-flight audit catches dangerous routes.   │
# └──────────────────────────────────────────────────────────────┘

from mcp_rampart import MCPRampart  # pip install mcp-rampart

rampart = MCPRampart(
    app,
    name="Mealie Recipe Manager",
    description="Self-hosted recipe manager — search recipes, plan meals, manage shopping lists",
    exclude_paths=["*/auth/*", "*/admin/*"],
)

# Optional: customize specific tools for better LLM understanding
rampart.tool("/api/recipes/search", description="Search recipes by name, ingredients, or keywords. Use this to find what to cook.")
rampart.tool("/api/households/mealplans", description="View the weekly meal plan. Shows what's planned for breakfast, lunch, and dinner.")


# ═══════════════════════════════════════════════════════════════════
# 5. RUN
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn

    # Print the bridge summary
    print("\n" + rampart.summary() + "\n")

    # Pre-flight security audit — never expose your API to LLMs blind
    report = rampart.audit()
    report.print_text()
    if report.has_blockers():
        print("\n❌ Audit found CRITICAL issues — refusing to start. Fix the issues above.")
        raise SystemExit(1)

    # Runtime guardrails — scan every tools/call for prompt-injection patterns
    rampart.enable_guardrails(policy="block")

    print("\n🚀 Starting Mealie with MCPRampart...")
    print("   App:        http://localhost:9925/docs")
    print("   MCP:        http://localhost:9925/mcp")
    print("   Guardrails: block-on-injection (every tools/call is scanned)")
    print()

    uvicorn.run(app, host="0.0.0.0", port=9925)
